import { Webhook } from "svix"; // ✅ Used for verifying Clerk webhooks
import connectDB from "@/config/db";
import User from "@/models/User";
import { NextResponse } from "next/server";

export async function POST(req) {
  const wh = new Webhook(process.env.SIGNING_SECRET);

  const headerPayload = req.headers;
  const svixHeaders = {
    "svix-id": headerPayload.get("svix-id"),
    "svix-timestamp": headerPayload.get("svix-timestamp"),
    "svix-signature": headerPayload.get("svix-signature"),
  };

  const payload = await req.json();
  const body = JSON.stringify(payload);

  let data, type;

  // ✅ ADDED: Try-catch block to safely verify the webhook signature
  try {
    ({ data, type } = wh.verify(body, svixHeaders));
  } catch (err) {
    console.error("Webhook verification failed:", err); // ✅ ADDED: Log verification errors
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 }); // ✅ ADDED: Return 400 on signature failure
  }

  // ✅ ADDED: Guard clause to prevent crashing on missing or empty email_addresses
  if (!data || !Array.isArray(data.email_addresses) || data.email_addresses.length === 0) {
    return NextResponse.json({ error: "Invalid user data" }, { status: 400 });
  }

  // ✅ CHANGED: Safe optional chaining + fallback values added
  const userData = {
    _id: data.id,
    email: data.email_addresses[0]?.email_address || null, // ✅ ADDED: Safe optional chaining
    name: `${data.first_name || ""} ${data.last_name || ""}`.trim(), // ✅ ADDED: Fallback for undefined names
    image: data.image_url || null, // ✅ ADDED: Fallback for missing profile image
  };

  try {
    await connectDB();

    switch (type) {
      case "user.created":
        await User.create(userData);
        break;

      case "user.updated":
        await User.findByIdAndUpdate(data.id, userData);
        break;

      case "user.deleted":
        await User.findByIdAndDelete(data.id);
        break;

      default:
        console.warn("Unhandled event type:", type); // ✅ ADDED: Log unhandled webhook types
        break;
    }

    return NextResponse.json({ message: "Event received" });
  } catch (err) {
    console.error("Database error:", err); // ✅ ADDED: Error logging for DB issues
    return NextResponse.json({ error: "Internal server error" }, { status: 500 }); // ✅ ADDED: 500 response for DB errors
  }
}
