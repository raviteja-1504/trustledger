import { redirect } from "next/navigation";
import { threatsHref } from "@/lib/threatRoutes";

/** Now the "alerts" tab of the Threats page; links and bookmarks to this address keep working. */
export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  redirect(threatsHref("alerts", await searchParams));
}
