import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { ShieldCheck, Cpu, Info, ChevronDown } from "lucide-react";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "PhishGuard AI | ML-Based Phishing URL Detection System",
  description:
    "Analyse website URLs using machine learning, website structure and security features to identify potentially malicious websites.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark scroll-smooth">
      <body
        className={`${inter.className} bg-[#0B0F19] text-slate-100 min-h-screen flex flex-col selection:bg-blue-500/30 selection:text-blue-200 antialiased`}
      >
        {/* Ambient background color */}
        <div aria-hidden="true" className="fixed inset-0 pointer-events-none overflow-hidden -z-10">
          <div className="absolute -top-40 left-1/4 h-96 w-96 rounded-full bg-cyan-500/[0.08] blur-3xl" />
          <div className="absolute top-20 right-1/4 h-96 w-96 rounded-full bg-indigo-500/[0.08] blur-3xl" />
        </div>

        {/* Navigation Bar */}
        <header className="sticky top-0 z-50 border-b border-slate-700/70 bg-[#080d18]/90 backdrop-blur-xl">
          <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
            {/* Brand Logo */}
            <a href="#home" className="group flex min-w-0 items-center gap-3 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300">
              <div className="rounded-xl border border-cyan-300/25 bg-cyan-400/10 p-2 transition-colors group-hover:border-cyan-300/50">
                <ShieldCheck className="h-6 w-6 text-cyan-300" />
              </div>
              <div className="flex min-w-0 flex-col">
                <span className="truncate bg-gradient-to-r from-white to-cyan-100 bg-clip-text text-lg font-bold tracking-tight text-transparent">
                  PhishGuard AI
                </span>
                <span className="hidden text-[10px] font-medium uppercase tracking-widest text-slate-300 sm:block">
                  MLP Neural Threat Engine
                </span>
              </div>
            </a>

            {/* Navigation Links */}
            <nav aria-label="Main navigation" className="hidden items-center gap-8 text-sm font-medium text-slate-200 md:flex">
              <a
                href="#home"
                className="flex items-center gap-1.5 transition-colors hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300"
              >
                Home
              </a>
              <a
                href="#how-it-works"
                className="flex items-center gap-1.5 transition-colors hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300"
              >
                <Cpu className="h-4 w-4 text-indigo-300" />
                How It Works
              </a>
              <a
                href="#about"
                className="flex items-center gap-1.5 transition-colors hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300"
              >
                <Info className="h-4 w-4 text-cyan-300" />
                About
              </a>
            </nav>

            <details className="group relative md:hidden">
              <summary className="flex cursor-pointer list-none items-center gap-2 rounded-lg border border-slate-600/80 px-3 py-2 text-sm font-medium text-slate-100 transition-colors hover:border-cyan-300/50 hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300 [&::-webkit-details-marker]:hidden">
                Menu
                <ChevronDown aria-hidden="true" className="h-3.5 w-3.5 transition-transform group-open:rotate-180" />
              </summary>
              <nav aria-label="Mobile navigation" className="absolute right-0 top-full mt-3 flex w-52 flex-col gap-1 rounded-xl border border-slate-700 bg-slate-900 p-2 shadow-2xl shadow-black/40">
                <a href="#home" className="rounded-lg px-3 py-2.5 text-sm text-slate-100 hover:bg-slate-800 hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300">Home</a>
                <a href="#how-it-works" className="rounded-lg px-3 py-2.5 text-sm text-slate-100 hover:bg-slate-800 hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300">How It Works</a>
                <a href="#about" className="rounded-lg px-3 py-2.5 text-sm text-slate-100 hover:bg-slate-800 hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300">About</a>
              </nav>
            </details>
          </div>
        </header>

        {/* Main Page Content */}
        <main className="flex-1">{children}</main>

        {/* Footer */}
        <footer className="mt-20 border-t border-slate-700/70 bg-[#070b14] py-8">
          <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-4 text-center text-xs text-slate-300 sm:flex-row sm:px-6 sm:text-left lg:px-8">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 shrink-0 text-cyan-300" />
              <span>
                PhishGuard AI · Website security analysis
              </span>
            </div>
            <p>Machine-learning URL analysis · Website security signals</p>
          </div>
        </footer>
      </body>
    </html>
  );
}