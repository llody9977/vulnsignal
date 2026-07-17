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
  title: "VulnSignal — CVE & KEV Trend Intelligence",
  description:
    "An evidence-led dashboard for CVE publication, severity, exploit references, and CISA Known Exploited Vulnerabilities trends.",
  applicationName: "VulnSignal",
  authors: [{ name: "VulnSignal contributors" }],
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
    title: "VulnSignal — See the shift. Prioritize the risk.",
    description:
      "Daily CVE and KEV trend intelligence from authoritative public sources.",
    siteName: "VulnSignal",
    images: [
      {
        url: "og.png",
        width: 1730,
        height: 909,
        alt: "VulnSignal — See the shift. Prioritize the risk.",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "VulnSignal — CVE & KEV Trend Intelligence",
    description:
      "Daily vulnerability signal from CVE, NVD, and CISA KEV sources.",
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
