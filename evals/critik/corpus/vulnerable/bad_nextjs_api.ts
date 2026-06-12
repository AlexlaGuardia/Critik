// Intentionally vulnerable Next.js code for testing
// Fake path: app/api/users/route.ts

export async function POST(request: Request) {
  const body = await request.json()
  // No auth check — anyone can create users
  await db.user.create({ data: body })
  return Response.json({ ok: true })
}

export async function DELETE(request: Request) {
  const { id } = await request.json()
  await db.user.delete({ where: { id } })
  return Response.json({ ok: true })
}

// Secret leaked via NEXT_PUBLIC prefix
const key = process.env.NEXT_PUBLIC_SECRET_API_KEY
const dbUrl = process.env.NEXT_PUBLIC_DATABASE_URL
