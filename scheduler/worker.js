const API = "https://api.github.com";
const REPO_RE = /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/;
const FILE_RE = /^[A-Za-z0-9._-]+\.ya?ml$/;
const WEBHOOK_PREFIXES = ["https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/"];

export function kstDate(time) {
  return new Date(time + 9 * 3600 * 1000).toISOString().slice(0, 10);
}

function config(env) {
  if (!REPO_RE.test(env.GH_REPO || "") || !FILE_RE.test(env.WORKFLOW_FILE || "") || !env.GITHUB_TOKEN) {
    throw new Error("scheduler config invalid");
  }
  return { repo: env.GH_REPO, workflow: env.WORKFLOW_FILE, token: env.GITHUB_TOKEN };
}

function github(cfg, path, init = {}) {
  return fetch(`${API}${path}`, {
    ...init,
    redirect: "manual",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${cfg.token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "security-briefing-scheduler",
      ...(init.headers || {}),
    },
  });
}

async function postExists(cfg, date) {
  const res = await github(cfg, `/repos/${cfg.repo}/contents/_posts/${date}-security-briefing.md?ref=main`);
  if (res.status === 200) return true;
  if (res.status === 404) return false;
  throw new Error(`post check failed: HTTP ${res.status}`);
}

async function dispatch(cfg) {
  const res = await github(cfg, `/repos/${cfg.repo}/actions/workflows/${cfg.workflow}/dispatches`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ref: "main" }),
  });
  if (res.status !== 204) throw new Error(`dispatch failed: HTTP ${res.status}`);
}

async function alert(env, text) {
  const url = env.DISCORD_WEBHOOK_URL || "";
  if (!WEBHOOK_PREFIXES.some((p) => url.startsWith(p))) return;
  await fetch(url, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: text, allowed_mentions: { parse: [] } }),
  });
}

export async function run(cron, time, env) {
  const cfg = config(env);
  const date = kstDate(time);
  if (await postExists(cfg, date)) return "exists";
  if (cron === env.WATCHDOG_CRON) {
    await alert(env, `⚠️ ${date} 보안 브리핑이 아직 없어 다시 실행합니다.`);
  }
  await dispatch(cfg);
  return "dispatched";
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      run(event.cron, event.scheduledTime, env).catch(async (err) => {
        await alert(env, `❌ 브리핑 스케줄러 오류: ${String(err.message).slice(0, 120)}`);
        throw err;
      }),
    );
  },
  async fetch() {
    return new Response("Not Found", { status: 404 });
  },
};
