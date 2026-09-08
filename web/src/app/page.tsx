/** `/` has no page of its own — send the user to the scan list. */
import { redirect } from "next/navigation";

export default function RootPage() {
  redirect("/scans");
}
