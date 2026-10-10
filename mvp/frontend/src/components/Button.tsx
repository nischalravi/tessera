import { ButtonHTMLAttributes, ReactNode, forwardRef } from "react";
import { Link, LinkProps } from "react-router-dom";

type Variant = "default" | "primary" | "danger" | "danger-solid" | "ghost";

function cls(variant: Variant, size?: "sm", iconOnly?: boolean, extra?: string) {
  const v = variant === "danger-solid" ? "danger solid" : variant === "default" ? "" : variant;
  return ["btn", v, size, iconOnly ? "icon" : "", extra].filter(Boolean).join(" ");
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: "sm";
  icon?: ReactNode;
  /** Keyboard hint shown after the label, e.g. "A". */
  kbd?: string;
  /** Icon-only button. `aria-label` (or `label`) is required for accessibility. */
  label?: string;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "default", size, icon, kbd, label, className, children, type, ...rest },
  ref,
) {
  const iconOnly = !children && !!icon;
  return (
    <button
      ref={ref}
      type={type ?? "button"}
      className={cls(variant, size, iconOnly, className)}
      aria-label={iconOnly ? (rest["aria-label"] ?? label) : rest["aria-label"]}
      title={iconOnly ? (rest.title ?? label) : rest.title}
      {...rest}
    >
      {icon}
      {children}
      {kbd && <span className="kbd" aria-hidden>{kbd}</span>}
    </button>
  );
});

export function ButtonLink({ variant = "default", size, icon, children, className, ...rest }: LinkProps & { variant?: Variant; size?: "sm"; icon?: ReactNode }) {
  return (
    <Link className={cls(variant, size, false, className as string)} {...rest}>
      {icon}
      {children}
    </Link>
  );
}
