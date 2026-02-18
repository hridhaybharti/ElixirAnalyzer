import axios from "axios";
import { secretsManager } from "./secrets";
import { Analysis } from "@shared/schema";

/**
 * Collaboration Webhook Service
 * Sends real-time alerts to Slack/Discord for high-risk threats.
 */
class WebhookService {
  private static instance: WebhookService;

  private constructor() {}

  public static getInstance(): WebhookService {
    if (!WebhookService.instance) {
      WebhookService.instance = new WebhookService();
    }
    return WebhookService.instance;
  }

  public async notifyHighRisk(analysis: Analysis) {
    const webhookUrl = secretsManager.getSecret("SECURITY_WEBHOOK_URL");
    if (!webhookUrl || analysis.riskScore < 70) return;

    console.log(`[WebhookService] Sending alert for ${analysis.input}`);

    const payload = {
      text: `🚨 *High Risk Threat Detected* 🚨`,
      blocks: [
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*Target:* \`${analysis.input}\`\n*Verdict:* ${analysis.riskLevel}\n*Score:* ${analysis.riskScore}/100`,
          },
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `> ${analysis.summary}`,
          },
        },
        {
          type: "context",
          elements: [
            { type: "mrkdwn", text: `Powered by Elixir Analyzer | ID: ${analysis.id}` },
          ],
        },
      ],
    };

    try {
      await axios.post(webhookUrl, payload, { timeout: 5000 });
    } catch (error: any) {
      console.error(`[WebhookService] Failed to send webhook:`, error.message);
    }
  }
}

export const webhookService = WebhookService.getInstance();
