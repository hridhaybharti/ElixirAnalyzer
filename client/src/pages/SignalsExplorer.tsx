import React, { useMemo, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface SignalInfo {
  name: string;
  category: string;
  bucket: string;
  typical_impact: number;
  typical_confidence: number;
  description: string;
  examples: string[];
}

const SIGNAL_DATABASE: SignalInfo[] = [
  {
    name: "Domain Age",
    category: "domain",
    bucket: "reputation",
    typical_impact: 30,
    typical_confidence: 0.75,
    description: "Domain has been registered recently (less than 30 days old)",
    examples: ["Newly registered malware domains", "Phishing campaigns"],
  },
  {
    name: "Typosquatting Suspected",
    category: "domain",
    bucket: "structure",
    typical_impact: 32,
    typical_confidence: 0.8,
    description: "Domain appears to be a typo of a protected brand",
    examples: ["gogle.com (google)", "amaz0n.com (amazon)"],
  },
  {
    name: "Homoglyph Lookalike Detected",
    category: "domain",
    bucket: "structure",
    typical_impact: 35,
    typical_confidence: 0.85,
    description: "Domain uses visual lookalike characters (homoglyphs)",
    examples: ["gооgle.com (Cyrillic o)", "mіcrosoft.com (Latin i)"],
  },
  {
    name: "Suspicious TLD",
    category: "domain",
    bucket: "structure",
    typical_impact: 25,
    typical_confidence: 0.75,
    description: "Domain uses a TLD with high abuse correlation",
    examples: [".tk", ".ml", ".ga", ".cf", ".top"],
  },
  {
    name: "Parked Domain Suspected",
    category: "domain",
    bucket: "reputation",
    typical_impact: 12,
    typical_confidence: 0.55,
    description: "Domain appears to be parked (empty/placeholder content)",
    examples: ["Domains with parking NS records", "No MX records"],
  },
  {
    name: "IDN/Punycode",
    category: "domain",
    bucket: "structure",
    typical_impact: 15,
    typical_confidence: 0.6,
    description: "Domain uses punycode encoding (internationalized domain names)",
    examples: ["xn--... domains"],
  },
  {
    name: "Registrar Reputation",
    category: "domain",
    bucket: "reputation",
    typical_impact: 10,
    typical_confidence: 0.5,
    description: "Registrar has known privacy/proxying services",
    examples: ["Whoisguard", "Privacy protection services"],
  },
  {
    name: "DNS Nameservers",
    category: "domain",
    bucket: "network",
    typical_impact: 12,
    typical_confidence: 0.7,
    description: "Missing or suspicious DNS nameserver configuration",
    examples: ["No NS records", "Suspicious hosting providers"],
  },
  {
    name: "DNS A/AAAA",
    category: "domain",
    bucket: "network",
    typical_impact: 14,
    typical_confidence: 0.75,
    description: "Domain does not resolve to any IP address",
    examples: ["Non-resolving domains", "Broken DNS records"],
  },
  {
    name: "Top-Tier Reputable Domain",
    category: "domain",
    bucket: "reputation",
    typical_impact: -65,
    typical_confidence: 0.98,
    description: "Domain is a globally recognized reputable service",
    examples: ["google.com", "microsoft.com", "github.com"],
  },
];

export default function SignalsExplorer() {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedBucket, setSelectedBucket] = useState<string | null>(null);

  const filteredSignals = useMemo(() => {
    return SIGNAL_DATABASE.filter((signal) => {
      const matchesSearch = signal.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        signal.description.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesBucket = !selectedBucket || signal.bucket === selectedBucket;
      return matchesSearch && matchesBucket;
    });
  }, [searchTerm, selectedBucket]);

  const bucketStats = useMemo(() => {
    const stats: Record<string, number> = {};
    SIGNAL_DATABASE.forEach((s) => {
      stats[s.bucket] = (stats[s.bucket] || 0) + 1;
    });
    return stats;
  }, []);

  const getBucketColor = (bucket: string) => {
    switch (bucket) {
      case "reputation":
        return "bg-red-900 text-red-200";
      case "structure":
        return "bg-yellow-900 text-yellow-200";
      case "network":
        return "bg-blue-900 text-blue-200";
      default:
        return "bg-slate-700 text-slate-200";
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 py-8">
      <div className="max-w-4xl mx-auto px-4 space-y-6">
        {/* Header */}
        <div className="space-y-2">
          <h1 className="text-3xl font-bold">Signal Explorer</h1>
          <p className="text-slate-400">
            Browse all detection signals and understand how risk is calculated
          </p>
        </div>

        {/* Search and Filter */}
        <div className="space-y-3">
          <Input
            placeholder="Search signals by name or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-slate-800 border-slate-700 text-slate-200 placeholder:text-slate-500"
          />

          <div className="flex gap-2 flex-wrap">
            <button
              onClick={() => setSelectedBucket(null)}
              className={`px-3 py-1 rounded text-sm transition ${
                selectedBucket === null
                  ? "bg-emerald-600 text-white"
                  : "bg-slate-800 text-slate-300 hover:bg-slate-700"
              }`}
            >
              All ({SIGNAL_DATABASE.length})
            </button>
            {Object.entries(bucketStats).map(([bucket, count]) => (
              <button
                key={bucket}
                onClick={() => setSelectedBucket(bucket)}
                className={`px-3 py-1 rounded text-sm transition ${
                  selectedBucket === bucket
                    ? "bg-emerald-600 text-white"
                    : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                }`}
              >
                {bucket} ({count})
              </button>
            ))}
          </div>
        </div>

        {/* Signals Grid */}
        <div className="grid gap-4">
          {filteredSignals.map((signal) => (
            <Card key={signal.name} className="bg-slate-900 border-slate-700 hover:border-slate-600 transition">
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <CardTitle className="text-lg">{signal.name}</CardTitle>
                    <CardDescription className="text-slate-400 mt-1">
                      {signal.description}
                    </CardDescription>
                  </div>
                  <Badge className={getBucketColor(signal.bucket)}>
                    {signal.bucket}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                {/* Impact and Confidence */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-slate-800 rounded p-2">
                    <p className="text-xs text-slate-400 uppercase">Impact</p>
                    <p className={`text-lg font-bold ${signal.typical_impact > 0 ? "text-red-400" : signal.typical_impact < 0 ? "text-green-400" : "text-slate-300"}`}>
                      {signal.typical_impact > 0 ? "+" : ""}{signal.typical_impact}
                    </p>
                  </div>
                  <div className="bg-slate-800 rounded p-2">
                    <p className="text-xs text-slate-400 uppercase">Confidence</p>
                    <p className="text-lg font-bold text-blue-400">
                      {(signal.typical_confidence * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>

                {/* Examples */}
                {signal.examples.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-400 uppercase mb-2">Common Examples</p>
                    <div className="flex gap-2 flex-wrap">
                      {signal.examples.map((ex, idx) => (
                        <Badge key={idx} variant="secondary" className="text-xs">
                          {ex}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Info Section */}
        <Card className="bg-slate-900 border-slate-700">
          <CardHeader>
            <CardTitle className="text-lg">Understanding Risk Buckets</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Badge className={getBucketColor("reputation")}>reputation</Badge>
              <p className="text-sm text-slate-300 mt-1">
                Signals related to domain/IP reputation, age, registrar, and known bad lists
              </p>
            </div>
            <div>
              <Badge className={getBucketColor("structure")}>structure</Badge>
              <p className="text-sm text-slate-300 mt-1">
                Signals related to domain structure, typos, homoglyphs, and URL patterns
              </p>
            </div>
            <div>
              <Badge className={getBucketColor("network")}>network</Badge>
              <p className="text-sm text-slate-300 mt-1">
                Signals related to network infrastructure, DNS, IPs, and ASNs
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
