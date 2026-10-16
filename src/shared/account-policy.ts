export function isDemoDeployment(deployType?: string): boolean {
  return deployType?.toLowerCase() === 'demo';
}

export function getAccountPolicy(deployType?: string): { bootstrapUsernameMinLength: number; passwordMinLength: number } {
  const demo = isDemoDeployment(deployType);
  return { bootstrapUsernameMinLength: demo ? 1 : 3, passwordMinLength: demo ? 1 : 8 };
}
