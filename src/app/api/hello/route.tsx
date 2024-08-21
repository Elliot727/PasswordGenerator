import { NextRequest, NextResponse } from 'next/server';
import { generateSecurePassword } from '../pages';
export async function POST(req: NextRequest) {
  const { master, url, seed, prefix, size } = await req.json();

  if (!master || !url || !seed || !size) {
    return NextResponse.json({ error: 'Invalid input. Please ensure all required fields are filled.' }, { status: 400 });
  }

  try {
    const password = generateSecurePassword(master, url, seed, prefix, parseInt(size, 10));
    return NextResponse.json({ password });
  } catch (error) {
    return NextResponse.json({ error: 'Error generating password' }, { status: 500 });
  }
}

export async function GET(req: NextRequest) {
  return NextResponse.json({ message: 'Method not allowed' }, { status: 405 });
}

export async function PUT(req: NextRequest) {
  return NextResponse.json({ message: 'Method not allowed' }, { status: 405 });
}

export async function DELETE(req: NextRequest) {
  return NextResponse.json({ message: 'Method not allowed' }, { status: 405 });
}
