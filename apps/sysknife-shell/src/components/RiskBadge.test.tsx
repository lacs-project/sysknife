import { render, screen } from "@testing-library/react";
import { RiskBadge } from "./RiskBadge";

describe("RiskBadge", () => {
  it("renders LOW with green text", () => {
    render(<RiskBadge level="low" />);
    const badge = screen.getByLabelText("low risk");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveStyle({ color: "#4ade80" });
  });

  it("renders MEDIUM with amber text", () => {
    render(<RiskBadge level="medium" />);
    expect(screen.getByLabelText("medium risk")).toHaveStyle({ color: "#fb923c" });
  });

  it("renders HIGH with red text", () => {
    render(<RiskBadge level="high" />);
    expect(screen.getByLabelText("high risk")).toHaveStyle({ color: "#f87171" });
  });
});
