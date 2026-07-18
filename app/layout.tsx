import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_SITE_URL ??
      "https://llody9977.github.io/vulnsignal/",
  ),
  title: "VulnSignal — CVE, KEV and LLM Disclosure Trends",
  description:
    "Daily dashboard of CVE publications, CVSS severity, CISA KEV additions, public exploit references, current EPSS signals and documented LLM-assisted disclosures.",
  applicationName: "VulnSignal",
  authors: [{ name: "llody9977", url: "https://github.com/llody9977" }],
  keywords: [
    "CVE",
    "CISA KEV",
    "vulnerability intelligence",
    "cybersecurity dashboard",
    "vulnerability trends",
  ],
  alternates: {
    canonical: "./",
  },
  openGraph: {
    type: "website",
    url: "./",
    title: "VulnSignal — CVE, KEV and LLM disclosures. One timeline.",
    description:
      "Compare monthly CVE, severity, CISA KEV, exploit-reference, current EPSS and documented LLM disclosure data from official and first-party public sources.",
    siteName: "VulnSignal",
    images: [
      {
        url: "og.png",
        width: 1200,
        height: 630,
        alt: "VulnSignal dashboard showing CVE, KEV and LLM disclosure trends",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "VulnSignal — CVE, KEV and LLM Disclosure Trends",
    description:
      "Compare CVE, severity, KEV, exploit-reference, current EPSS and documented LLM disclosure data on one monthly timeline.",
    images: ["og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
