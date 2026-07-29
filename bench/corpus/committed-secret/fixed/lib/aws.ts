// Fixed: no secret value in source. The credentials are read from the server environment at
// runtime, so nothing sensitive is committed to the repository.
export const s3Config = {
  region: 'us-east-1',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
}
