/**
 * site.test.ts — OmniJarvis public website (hub-served HTML).
 *
 * The site is server-rendered HTML, so these tests assert the pages
 * contain the locked content (pricing numbers, UPI-only flow, APK
 * version/size, DPDP wipe, grievance placeholder) and that the
 * licence/admin pages kept their element IDs + API paths after the
 * redesign (the shell changed, the flows did not).
 */
import { describe, expect, it } from "vitest";
import {
  docsPage,
  downloadPage,
  landingPage,
  pricingPage,
  privacyPage,
  refundPage,
  termsPage,
} from "../src/site";
import { adminDashboardPage, adminLoginPage } from "../src/admin";
import { licenceLandingPage, licenceLoginPage } from "../src/licence-web";

describe("public site pages (site.ts)", () => {
  it("landing: hero + features + pricing preview + FAQ + footer", () => {
    const html = landingPage();
    expect(html).toContain("Your phone, your AI assistant");
    expect(html).toContain("Talker talks");
    expect(html).toContain("Executor works");
    expect(html).toContain("₹999");
    expect(html).toContain("/download");
    expect(html).toContain("/licence");
    expect(html).toContain("Privacy Policy");
    expect(html).toContain("Trained Jarvis");
  });

  it("pricing: locked tiers + annual 11x + UPI-only", () => {
    const html = pricingPage();
    expect(html).toContain("₹0");
    expect(html).toContain("₹999");
    expect(html).toContain("₹2,999");
    expect(html).toContain("₹10,989");
    expect(html).toContain("₹32,989");
    expect(html).toContain("2,500 AI replies");
    expect(html).toContain("7,500 AI replies");
    expect(html).toContain("100 AI replies");
    expect(html).toContain("UPI");
    expect(html).toContain("No card");
  });

  it("download: APK version + size + install-over rule", () => {
    const html = downloadPage();
    expect(html).toContain("1.21.0");
    expect(html).toContain("16.08 MiB");
    expect(html).toContain("12JJhfYAUCCGu6g35x6BcGNHPF1pJ5o1Z");
    expect(html).toContain("Skills");
    expect(html).toContain("Never uninstall");
    expect(html).toContain("drive.google.com");
  });

  it("docs: pairing + Talker/Executor + browser + troubleshooting", () => {
    const html = docsPage();
    expect(html).toContain("Pair your device");
    expect(html).toContain("Talker");
    expect(html).toContain("Executor");
    expect(html).toContain("in-app browser");
    expect(html).toContain("Trained Jarvis");
    expect(html).toContain("Troubleshooting");
  });

  it("legal: privacy (DPDP wipe + grievance placeholder) / terms / refund (UPI)", () => {
    const privacy = privacyPage();
    expect(privacy).toContain("DPDP");
    expect(privacy).toContain("Not yet appointed");
    expect(privacy).toContain("[REDACTED]");
    expect(termsPage()).toContain("BYOK");
    expect(termsPage()).toContain("One licence per user");
    const refund = refundPage();
    expect(refund).toContain("UPI");
    expect(refund).toContain("7 working days");
    expect(refund).toContain("Full refund");
  });

  it("licence pages kept their contracts after the redesign", () => {
    expect(licenceLandingPage()).toContain("Get your free licence");
    expect(licenceLandingPage()).toContain('id="email"');
    expect(licenceLandingPage()).toContain("/api/licence-web/signup");
    expect(licenceLoginPage()).toContain("/api/licence-web/login");
  });

  it("admin pages kept their contracts after the redesign", () => {
    expect(adminLoginPage()).toContain('id="email"');
    expect(adminLoginPage()).toContain("/api/licence-web/login");
    expect(adminLoginPage()).toContain("/api/licence-web/verify");
    const dash = adminDashboardPage("flipify.com@gmail.com");
    expect(dash).toContain("flipify.com@gmail.com");
    expect(dash).toContain('id="overview"');
    expect(dash).toContain('id="keys"');
    expect(dash).toContain('id="trainText"');
    expect(dash).toContain('id="jobs"');
    expect(dash).toContain('id="licences"');
    expect(dash).toContain("/api/admin/overview");
    expect(dash).toContain("/api/admin/keys");
    expect(dash).toContain("/api/admin/train");
    expect(dash).not.toContain("Loading…");
  });
});
