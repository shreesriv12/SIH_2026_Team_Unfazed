import "./style.css";
export const metadata = { title: "SecureMailScope", description: "Evidence-first email cryptography analysis" };
export default function Layout({ children }: Readonly<{children: React.ReactNode}>) { return <html lang="en"><body>{children}</body></html>; }
