import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";

interface BatchScanFormProps {
  onSubmit: (inputs: string[], maxConcurrent: number) => void;
  isLoading?: boolean;
}

export const BatchScanForm: React.FC<BatchScanFormProps> = ({ onSubmit, isLoading = false }) => {
  const [inputsText, setInputsText] = useState("");
  const [maxConcurrent, setMaxConcurrent] = useState(5);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const inputs = inputsText
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    if (inputs.length === 0) {
      alert("Please enter at least one domain/URL/IP");
      return;
    }

    if (inputs.length > 100) {
      alert("Maximum 100 inputs allowed per batch");
      return;
    }

    onSubmit(inputs, maxConcurrent);
  };

  const inputs = inputsText
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  return (
    <Card className="bg-slate-900 border-slate-700">
      <CardHeader>
        <CardTitle className="text-lg">Batch Scan</CardTitle>
        <CardDescription className="text-slate-400">
          Analyze up to 100 domains, URLs, or IPs at once
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Input Textarea */}
          <div className="space-y-2">
            <label className="text-sm font-medium text-slate-200">
              Targets (one per line)
            </label>
            <Textarea
              placeholder="example.com&#10;https://suspicious.xyz/page&#10;1.2.3.4"
              value={inputsText}
              onChange={(e) => setInputsText(e.target.value)}
              rows={8}
              className="bg-slate-800 border-slate-700 text-slate-200 placeholder:text-slate-500"
              disabled={isLoading}
            />
            <p className="text-xs text-slate-400">
              {inputs.length} inputs {inputs.length > 0 && `(${100 - inputs.length} remaining)`}
            </p>
          </div>

          {/* Concurrency Control */}
          <div className="space-y-2">
            <label className="text-sm font-medium text-slate-200">
              Max Concurrent Scans
            </label>
            <div className="flex items-center gap-2">
              <Input
                type="number"
                min="1"
                max="10"
                value={maxConcurrent}
                onChange={(e) => setMaxConcurrent(Math.min(10, Math.max(1, parseInt(e.target.value))))}
                className="w-20 bg-slate-800 border-slate-700 text-slate-200"
                disabled={isLoading}
              />
              <span className="text-xs text-slate-400">
                (Higher = faster, but more resources)
              </span>
            </div>
          </div>

          {/* Info Badges */}
          {inputs.length > 0 && (
            <div className="flex gap-2 flex-wrap">
              {inputs.slice(0, 3).map((input, idx) => (
                <Badge key={idx} variant="secondary" className="text-xs">
                  {input.length > 20 ? input.substring(0, 20) + "..." : input}
                </Badge>
              ))}
              {inputs.length > 3 && (
                <Badge variant="outline" className="text-xs">
                  +{inputs.length - 3} more
                </Badge>
              )}
            </div>
          )}

          {/* Submit Button */}
          <Button
            type="submit"
            disabled={isLoading || inputs.length === 0}
            className="w-full bg-emerald-600 hover:bg-emerald-700 text-white"
          >
            {isLoading ? "Scanning..." : `Scan ${inputs.length} Targets`}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
};
