import { createClient } from '@supabase/supabase-js';

export async function GET() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return Response.json(
      { error: 'Server configuration is unavailable.' },
      {
        status: 500,
        headers: {
          'Cache-Control': 'no-store',
        },
      }
    );
  }

  const supabase = createClient(supabaseUrl, supabaseSecretKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  const { data, error } = await supabase
    .from('notes')
    .select('title, content')
    .order('created_at', { ascending: true });

  if (error) {
    return Response.json(
      { error: 'Notes could not be loaded.' },
      {
        status: 500,
        headers: {
          'Cache-Control': 'no-store',
        },
      }
    );
  }

  return Response.json(
    {
      sampleMarker: 'SAMPLE_NOTE_1',
      notes: data,
    },
    {
      status: 200,
      headers: {
        'Cache-Control': 'no-store',
      },
    }
  );
}