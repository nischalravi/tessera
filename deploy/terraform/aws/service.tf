# ECS Fargate service (see deploy/aws/ecs-fargate for the same task definition as plain JSON), ALB with an
# ACM certificate, CloudWatch logs, least-privilege IAM.

resource "aws_cloudwatch_log_group" "this" {
  name              = "/${var.name}/prod"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Execution role: pulls images, writes logs, reads exactly the three secrets (nothing else).
resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_secrets" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for s in aws_secretsmanager_secret.this : s.arn]
  }
}

resource "aws_iam_role_policy" "execution_secrets" {
  name   = "read-tessera-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_secrets.json
}

# Task role: what the application itself may do. Only the audit anchor bucket.
resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "task" {
  statement {
    actions = [
      "s3:PutObject",
      "s3:PutObjectRetention",
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]
    resources = ["${aws_s3_bucket.anchors.arn}/*"]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "audit-anchor"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

resource "aws_ecs_cluster" "this" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = local.tags
}

locals {
  log_opts = {
    "awslogs-group"  = aws_cloudwatch_log_group.this.name
    "awslogs-region" = var.region
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  volume { name = "tessera-data" }
  volume { name = "api-tmp" }
  volume { name = "ui-tmp" }

  container_definitions = jsonencode([
    {
      name                   = "ui"
      image                  = var.ui_image
      essential              = true
      user                   = "101"
      readonlyRootFilesystem = true
      portMappings           = [{ containerPort = 8080, protocol = "tcp" }]
      environment            = [{ name = "API_UPSTREAM", value = "127.0.0.1:8000" }]
      dependsOn              = [{ containerName = "api", condition = "START" }]
      mountPoints            = [{ sourceVolume = "ui-tmp", containerPath = "/tmp" }]
      healthCheck = {
        command     = ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:8080/api/health || exit 1"]
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      linuxParameters  = { capabilities = { drop = ["ALL"] } }
      logConfiguration = { logDriver = "awslogs", options = merge(local.log_opts, { "awslogs-stream-prefix" = "ui" }) }
    },
    {
      name                   = "api"
      image                  = var.api_image
      essential              = true
      user                   = "65532"
      readonlyRootFilesystem = true
      command                = ["serve", "-addr", "0.0.0.0:8000"]
      portMappings           = [{ containerPort = 8000, protocol = "tcp" }]
      environment = [
        { name = "TESSERA_ENV", value = "prod" },
        { name = "TESSERA_PUBLIC_URL", value = var.public_url },
        { name = "TESSERA_COOKIE_SECURE", value = "true" },
        # nginx sidecar plus the VPC (the ALB nodes live in the public subnets of this /16)
        { name = "TESSERA_TRUSTED_PROXIES", value = "127.0.0.1/32,${var.vpc_cidr}" },
        { name = "TESSERA_AUDIT_ANCHOR", value = "s3://${aws_s3_bucket.anchors.bucket}/prod" },
        { name = "AWS_REGION", value = var.region },
        { name = "TESSERA_METRICS_ADDR", value = "off" },
      ]
      secrets = [
        { name = "TESSERA_DB", valueFrom = aws_secretsmanager_secret.this["db_owner_dsn"].arn },
        { name = "TESSERA_DB_APP", valueFrom = aws_secretsmanager_secret.this["db_app_dsn"].arn },
        { name = "TESSERA_KEK", valueFrom = aws_secretsmanager_secret.this["kek"].arn },
      ]
      mountPoints = [
        { sourceVolume = "tessera-data", containerPath = "/var/lib/tessera" },
        { sourceVolume = "api-tmp", containerPath = "/tmp" },
      ]
      linuxParameters  = { capabilities = { drop = ["ALL"] } }
      stopTimeout      = 30
      logConfiguration = { logDriver = "awslogs", options = merge(local.log_opts, { "awslogs-stream-prefix" = "api" }) }
    },
  ])
  tags = local.tags
}

resource "aws_lb" "this" {
  name_prefix                = "tsr-"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
  tags                       = local.tags
}

resource "aws_lb_target_group" "this" {
  name_prefix          = "tsr-"
  vpc_id               = aws_vpc.this.id
  port                 = 8080
  protocol             = "HTTP"
  target_type          = "ip"
  deregistration_delay = 30
  health_check {
    path                = "/api/health"
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
  tags = local.tags
  lifecycle { create_before_destroy = true }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_ecs_service" "this" {
  name                               = var.name
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.this.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  health_check_grace_period_seconds  = 60
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  enable_execute_command             = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "ui"
    container_port   = 8080
  }

  depends_on = [aws_lb_listener.https]
  tags       = local.tags
}
