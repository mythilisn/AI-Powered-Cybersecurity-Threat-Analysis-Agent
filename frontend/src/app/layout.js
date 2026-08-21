export const metadata = {
  title: 'SOC Threat Intelligence Agent',
  description: 'AI-Powered Threat Analysis & Sandboxing Platform',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0, backgroundColor: '#0a0d14' }}>
        {children}
      </body>
    </html>
  );
}