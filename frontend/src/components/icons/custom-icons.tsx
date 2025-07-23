interface IconProps {
  className?: string;
}

// Icons from Icons8 - https://icons8.com
// Used under free license with attribution for academic purposes

export const SqlInjectionIcon = ({ className }: IconProps) => (
  <img
    className={`${className} icons8-icon`}
    src="https://img.icons8.com/external-outline-black-m-oki-orlando/32/000000/external-sql-injection-cyber-security-outline-outline-black-m-oki-orlando.png"
    alt="SQL Injection Detection"
  />
);

export const XssIcon = ({ className }: IconProps) => (
  <img
    className={`${className} icons8-icon`}
    src="https://img.icons8.com/external-glyph-silhouettes-icons-papa-vector/78/000000/external-XSS-hacker-attack-glyph-silhouettes-icons-papa-vector.png"
    alt="XSS Vulnerability Scanner"
  />
);

export const WebInterfaceIcon = ({ className }: IconProps) => (
  <img
    className={`${className} icons8-icon`}
    src="https://img.icons8.com/external-smashingstocks-basic-outline-smashing-stocks/53/000000/external-web-interface-science-and-education-smashingstocks-basic-outline-smashing-stocks.png"
    alt="Web-Based Interface"
  />
);
