import type { z } from 'zod';

/**
 * The fields of a zod object schema for the type T, each one giving T's type for that field.
 * Written as `z.object({ … } satisfies SchemaOf<T>)`: a field added to T and not to the schema
 * (zod would drop it on save), or in the schema and not on T, does not compile.
 */
export type SchemaOf<T> = { [K in keyof Required<T>]: z.ZodType<T[K]> };
