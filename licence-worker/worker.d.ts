// Types for licence-worker/worker.js (plain JS; tsconfig has no allowJs,
// so this companion declaration keeps `tsc --noEmit` green).
declare const worker: {
  fetch(request: Request, env: Record<string, unknown>): Promise<Response>;
};
export default worker;
