// Planted benchmark fixture. These are AWS's DOCUMENTATION example keys (see
// docs.aws.amazon.com/IAM), NOT a live credential — they exist only to exercise the secret scanner.
// A committed value like this is graded as a P0 because it is a value match, not a name match.
export const s3Config = {
  region: 'us-east-1',
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
}
