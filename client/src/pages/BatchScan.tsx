import React, { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { BatchScanForm } from "@/components/BatchScanForm";
import { BatchScanResults } from "@/components/BatchScanResults";
import { AlertCircle } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";

interface BatchAnalyzeResponse {
  batch_id: string | null;
  total_inputs: number;
  completed: number;
  malicious_count: number;
  latency_ms: number;
  results: any[];
}

export default function BatchScan() {
  const [batchResults, setBatchResults] = useState<BatchAnalyzeResponse | null>(null);

  const batchMutation = useMutation({
    mutationFn: async (payload: { inputs: string[]; max_concurrent: number }) => {
      const response = await fetch("/api/batch_analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || "Batch analysis failed");
      }

      return response.json();
    },
    onSuccess: (data) => {
      setBatchResults(data);
    },
  });

  const handleBatchSubmit = (inputs: string[], maxConcurrent: number) => {
    setBatchResults(null);
    batchMutation.mutate({ inputs, max_concurrent: maxConcurrent });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 py-8">
      <div className="max-w-6xl mx-auto px-4 space-y-6">
        {/* Header */}
        <div className="space-y-2">
          <h1 className="text-3xl font-bold">Batch Scan</h1>
          <p className="text-slate-400">
            Analyze multiple domains, URLs, and IP addresses simultaneously
          </p>
        </div>

        {/* Error Alert */}
        {batchMutation.isError && (
          <Alert className="border-red-700 bg-red-950">
            <AlertCircle className="h-4 w-4 text-red-400" />
            <AlertDescription className="text-red-400 ml-3">
              {(batchMutation.error as Error).message}
            </AlertDescription>
          </Alert>
        )}

        {/* Form and Results */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <BatchScanForm
            onSubmit={handleBatchSubmit}
            isLoading={batchMutation.isPending}
          />

          {batchResults && (
            <BatchScanResults
              total={batchResults.total_inputs}
              completed={batchResults.completed}
              maliciousCount={batchResults.malicious_count}
              results={batchResults.results}
              latencyMs={batchResults.latency_ms}
            />
          )}
        </div>

        {/* Info Section */}
        {!batchResults && (
          <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
              <h3 className="font-semibold text-emerald-400 mb-2">⚡ Fast</h3>
              <p className="text-sm text-slate-400">
                Analyze multiple targets concurrently with configurable worker pool
              </p>
            </div>
            <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
              <h3 className="font-semibold text-emerald-400 mb-2">📊 Detailed</h3>
              <p className="text-sm text-slate-400">
                Each result includes risk scores, signals, and confidence metrics
              </p>
            </div>
            <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
              <h3 className="font-semibold text-emerald-400 mb-2">🛡️ Secure</h3>
              <p className="text-sm text-slate-400">
                Rate-limited API with request tracking and threat intelligence aggregation
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
