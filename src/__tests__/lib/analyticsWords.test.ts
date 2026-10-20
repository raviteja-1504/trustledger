/**
 * Analytics in plain words (lib/analyticsWords.ts).
 */
import { backlogSentence, clearSentence, duration, reviewSentence, shortDuration } from "@/lib/analyticsWords";

describe("durations", () => {
  it("read the way people say them", () => {
    expect(duration(null)).toBe("—");
    expect(duration(0.2)).toBe("12 minutes");
    expect(duration(0.001)).toBe("1 minute");
    expect(duration(1)).toBe("1 hour");
    expect(duration(5.4)).toBe("5 hours");
    expect(duration(47)).toBe("47 hours");
    expect(duration(48)).toBe("2 days");
    expect(duration(24 * 9.6)).toBe("10 days");
    expect(shortDuration(0.5)).toBe("30 min");
    expect(shortDuration(5.6)).toBe("6 h");
    expect(shortDuration(72)).toBe("3 days");
    expect(shortDuration(24)).toBe("24 h");
    expect(shortDuration(undefined)).toBe("—");
  });
});

describe("sentences", () => {
  const r = { severity: "CRITICAL", count: 12, median_hours: 5, p90_hours: 50, on_time: 10, with_deadline: 12 };
  it("review speed: half within, 9 in 10 within, on time", () => {
    expect(reviewSentence(r)).toBe("Half of the 12 CRITICAL sign-offs came within 5 hours of the scan, and 9 in 10 within 2 days. 10 of 12 were signed off before their fix deadline.");
    expect(reviewSentence({ ...r, count: 1, median_hours: 3, with_deadline: 0 })).toBe("The one CRITICAL sign-off came 3 hours after the scan.");
    expect(reviewSentence({ ...r, count: 0 })).toBe("No CRITICAL files were signed off in this period.");
  });
  it("open work", () => {
    expect(backlogSentence(5, 2)).toBe("3 more findings opened than closed — open work grew.");
    expect(backlogSentence(2, 3)).toBe("1 more finding closed than opened — open work shrank.");
    expect(backlogSentence(4, 4)).toBe("As many findings were closed as opened — open work held steady.");
    expect(backlogSentence(0, 0)).toBe("No findings were opened or closed in this period.");
  });
  it("time to clear", () => {
    expect(clearSentence(0, 1, 30, 0)).toBe("Nothing is waiting — every finding is closed.");
    expect(clearSentence(4, 0, 30, null)).toBe("4 findings open, and none were closed this period, so there's no pace to measure yet.");
    expect(clearSentence(9, 45, 30, 6)).toBe("At this period's pace (about 1.5 closed a day), the 9 open findings would all be closed in about 6 days.");
    expect(clearSentence(1, 60, 30, 0.4)).toBe("At this period's pace (about 2 closed a day), the 1 open finding would all be closed in about 1 day.");
    // A slow month: the rounded rate would read 0 a day; the count says what happened.
    expect(clearSentence(1, 1, 30, 30)).toBe("At this period's pace (1 finding closed in 30 days), the 1 open finding would all be closed in about 30 days.");
  });
});
