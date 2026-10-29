#!/bin/sh
# Import by the schedule's id (a UUID; list them with GET /api/v1/reviews/schedules).
# first_run_at is configuration and is not read back, so the first plan after an import shows it as a change to apply.
terraform import tessera_review_schedule.privileged_quarterly 6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f
