type Props = {
  inProgress?: boolean;
  label?: string;
};

export const SecuritySeal = ({
  inProgress = false,
  label = "Secure",
}: Props) => (
  <span
    className={`p-security-seal${inProgress ? " is-in-progress" : ""}`}
    title={
      inProgress ? "Security approval in progress" : "Security seal of approval"
    }
  >
    <svg
      className="p-security-seal__icon"
      viewBox="0 0 24 24"
      width="20"
      height="20"
      aria-hidden="true"
    >
      <path
        d="M12 1.5l2.2 1.6 2.7-.3 1.1 2.5 2.5 1.1-.3 2.7 1.6 2.2-1.6 2.2.3 2.7-2.5 1.1-1.1 2.5-2.7-.3L12 22.5l-2.2-1.6-2.7.3-1.1-2.5-2.5-1.1.3-2.7L2.2 12l1.6-2.2-.3-2.7 2.5-1.1 1.1-2.5 2.7.3z"
        fill="currentColor"
      />
      <path
        d="M7.5 12.2l3 3 6-6.2"
        fill="none"
        stroke="#fff"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
    <span className="p-security-seal__label">{label}</span>
  </span>
);

export type SealStatus = "approved" | "in-progress" | null;

// Demo assignment: a stable ~20% of charms are approved and ~20% in progress.
export const getSealStatus = (charmName: string): SealStatus => {
  let hash = 0;
  for (const char of charmName) {
    hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  }
  const bucket = hash % 10;
  if (bucket < 2) {
    return "approved";
  }
  if (bucket < 4) {
    return "in-progress";
  }
  return null;
};

export default SecuritySeal;
