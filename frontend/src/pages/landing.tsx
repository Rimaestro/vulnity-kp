import { Link } from 'react-router-dom'
import { ArrowRight, CheckCircle } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { AnimatedGradientText } from '@/components/magicui/animated-gradient-text'
import { NumberTicker } from '@/components/magicui/number-ticker'
import { ShimmerButton } from '@/components/magicui/shimmer-button'
import { BlurFade } from '@/components/magicui/blur-fade'
import Marquee from '@/components/magicui/marquee'
import Particles from '@/components/backgrounds/Particles'
import { SqlInjectionIcon, XssIcon, WebInterfaceIcon } from '@/components/icons/custom-icons'

export function LandingPage() {
  const features = [
    {
      icon: SqlInjectionIcon,
      title: 'SQL Injection Detection',
      description: 'Prototipe deteksi dasar kerentanan SQL Injection untuk pembelajaran keamanan web',
    },
    {
      icon: XssIcon,
      title: 'XSS Vulnerability Scanner',
      description: 'Identifikasi kerentanan Cross-Site Scripting (XSS) sebagai bagian penelitian keamanan',
    },
    {
      icon: WebInterfaceIcon,
      title: 'Web-Based Interface',
      description: 'Antarmuka berbasis web yang mudah digunakan, dirancang untuk pengguna non-teknis',
    },
  ]

  const benefits = [
    'Prototipe penelitian untuk pembelajaran keamanan web',
    'Antarmuka web yang mudah diakses tanpa instalasi CLI',
    'Fokus pada dua kerentanan umum: SQL Injection dan XSS',
    'Dirancang khusus untuk pengguna non-teknis dan pemula',
    'Dikembangkan menggunakan metode Research & Development',
    'Studi kasus menggunakan DVWA (Damn Vulnerable Web Application)',
  ]

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <img src="/logo.svg" alt="Vulnity Logo" className="h-10 w-10" />
            <h1 className="text-2xl font-bold">Vulnity</h1>
          </div>
          <div className="flex items-center space-x-4">
            <Link to="/login">
              <Button variant="ghost">Masuk</Button>
            </Link>
            <Link to="/register">
              <Button>Daftar</Button>
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative py-20 px-4 overflow-hidden">
        <div className="absolute inset-0 z-0">
          <Particles
            particleCount={150}
            particleSpread={8}
            speed={0.05}
            particleColors={['#ffffff', '#f8fafc', '#e2e8f0']}
            moveParticlesOnHover={true}
            particleHoverFactor={0.5}
            alphaParticles={true}
            particleBaseSize={80}
            sizeRandomness={0.8}
            cameraDistance={15}
            disableRotation={false}
          />
        </div>
        <div className="container mx-auto text-center relative z-10">
          <BlurFade delay={0.25} inView>
            <div className="flex justify-center mb-4">
              <ShimmerButton
                shimmerColor="#ffffff"
                shimmerSize="0.02em"
                shimmerDuration="2s"
                borderRadius="6px"
                background="#0f172a"
                className="px-3 py-1 text-xs font-medium border-transparent text-white hover:opacity-90 cursor-default !text-white !bg-slate-900"
              >
                Vulnerability Scanner
              </ShimmerButton>
            </div>
          </BlurFade>

          <BlurFade delay={0.5} inView>
            <h1 className="text-4xl md:text-6xl font-bold mb-6">
              Pelajari Keamanan Web dengan{' '}
              <AnimatedGradientText
                colorFrom="hsl(0, 0%, 3.9%)"
                colorTo="hsl(0, 0%, 45.1%)"
              >
                Vulnity
              </AnimatedGradientText>
            </h1>
          </BlurFade>

          <BlurFade delay={0.75} inView>
            <p className="text-xl text-muted-foreground mb-6 max-w-2xl mx-auto">
              Prototipe web vulnerability scanner berbasis antarmuka web untuk pembelajaran
              deteksi kerentanan SQL Injection dan XSS. Dikembangkan sebagai proyek penelitian
              dengan fokus pada kemudahan penggunaan bagi pengguna non-teknis.
            </p>
          </BlurFade>

          {/* Statistics */}
          <BlurFade delay={1.0} inView>
            <div className="flex flex-wrap justify-center items-center gap-12 mb-8 max-w-4xl mx-auto">
              <div className="flex flex-col items-center text-center min-w-[120px]">
                <div className="text-3xl md:text-4xl font-bold text-primary mb-1">
                  <NumberTicker value={2} />
                </div>
                <span className="text-sm text-muted-foreground font-medium">Jenis Kerentanan</span>
              </div>
              <div className="flex flex-col items-center text-center min-w-[120px]">
                <div className="text-3xl md:text-4xl font-bold text-primary mb-1">
                  <NumberTicker value={100} />%
                </div>
                <span className="text-sm text-muted-foreground font-medium">Berbasis Web</span>
              </div>
              <div className="flex flex-col items-center text-center min-w-[120px]">
                <div className="text-3xl md:text-4xl font-bold text-primary mb-1">
                  <NumberTicker value={0} />
                </div>
                <span className="text-sm text-muted-foreground font-medium">Instalasi CLI</span>
              </div>
            </div>
          </BlurFade>

          <BlurFade delay={1.25} inView>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link to="/register">
                <Button size="lg" className="w-full sm:w-auto">
                  Mulai Eksplorasi
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </Link>
              <Link to="/login">
                <Button variant="outline" size="lg" className="w-full sm:w-auto">
                  Akses Prototipe
                </Button>
              </Link>
            </div>
          </BlurFade>
        </div>
      </section>

      {/* Academic Research Tech Stack Marquee */}
      <section className="py-10 border-y bg-gradient-to-r from-muted/20 via-background to-muted/20">
        <div className="container mx-auto">
          <BlurFade delay={0.25} inView>
            <div className="text-center mb-6">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
                Research & Development Stack
              </h3>
            </div>
            <Marquee pauseOnHover forceAnimation className="[--duration:35s]">
              <div className="flex items-center space-x-12">
                {[
                  {
                    title: "Backend Framework",
                    tech: "FastAPI",
                    desc: "High-performance Python API",
                    badge: "Python",
                    icon: "https://img.icons8.com/ios/50/FFFFFF/python--v1.png"
                  },
                  {
                    title: "Frontend Stack",
                    tech: "React + TypeScript",
                    desc: "Modern web development",
                    badge: "JavaScript",
                    icon: "https://img.icons8.com/ios/50/FFFFFF/javascript--v1.png"
                  },
                  {
                    title: "Research Method",
                    tech: "R&D Approach",
                    desc: "Systematic development",
                    badge: "Methodology",
                    icon: "https://img.icons8.com/external-solidglyph-m-oki-orlando/50/FFFFFF/external-methodology-science-solid-solidglyph-m-oki-orlando.png"
                  },
                  {
                    title: "Development Model",
                    tech: "Waterfall",
                    desc: "Sequential phases",
                    badge: "Process",
                    icon: "https://img.icons8.com/ios/50/FFFFFF/process--v1.png"
                  },
                  {
                    title: "Security Focus",
                    tech: "SQL Injection",
                    desc: "Database vulnerability",
                    badge: "Detection",
                    icon: "https://img.icons8.com/ios/50/FFFFFF/detective.png"
                  },
                  {
                    title: "Web Security",
                    tech: "XSS Scanner",
                    desc: "Cross-site scripting",
                    badge: "Analysis",
                    icon: "https://img.icons8.com/ios/50/FFFFFF/bug.png"
                  },
                  {
                    title: "User Interface",
                    tech: "Web-Based",
                    desc: "No CLI required",
                    badge: "Accessibility",
                    icon: "https://img.icons8.com/ios/50/FFFFFF/accessibility2.png"
                  },
                ].map((item, index) => (
                  <div
                    key={index}
                    className="group flex flex-col items-center space-y-3 min-w-[200px] p-4 rounded-lg hover:bg-card hover:shadow-sm border border-transparent hover:border-border transition-all duration-300"
                  >
                    <div className="flex items-center space-x-2">
                      <span className="flex items-center space-x-2 px-3 py-1 text-xs font-medium bg-primary/10 text-primary rounded-full border border-primary/20">
                        <img
                          src={item.icon}
                          alt={item.badge}
                          className="w-4 h-4 filter brightness-0 invert"
                        />
                        <span>{item.badge}</span>
                      </span>
                    </div>
                    <div className="text-center">
                      <h4 className="font-semibold text-sm text-foreground group-hover:text-primary transition-colors">
                        {item.tech}
                      </h4>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                        {item.desc}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </Marquee>
          </BlurFade>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 px-4 bg-muted/50">
        <div className="container mx-auto">
          <BlurFade delay={0.25} inView>
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold mb-4">Fitur Prototipe</h2>
              <p className="text-muted-foreground max-w-2xl mx-auto">
                Vulnity menyediakan fitur-fitur dasar untuk pembelajaran deteksi kerentanan
                SQL Injection dan XSS melalui antarmuka web yang mudah dipahami.
              </p>
            </div>
          </BlurFade>

          <div className="grid md:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <BlurFade key={index} delay={0.5 + index * 0.2} inView>
                <Card className="text-center">
                  <CardHeader>
                    <feature.icon className="h-12 w-12 text-primary mx-auto mb-4" />
                    <CardTitle>{feature.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription>{feature.description}</CardDescription>
                  </CardContent>
                </Card>
              </BlurFade>
            ))}
          </div>
        </div>
      </section>

      {/* Benefits Section */}
      <section className="py-20 px-4">
        <div className="container mx-auto">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <BlurFade delay={0.25} inView>
              <div>
                <h2 className="text-3xl font-bold mb-6">
                  Tentang Proyek Vulnity
                </h2>
                <p className="text-muted-foreground mb-8">
                  Vulnity dikembangkan sebagai proyek penelitian untuk menciptakan
                  prototipe vulnerability scanner yang lebih mudah diakses, khususnya
                  untuk pembelajaran keamanan web bagi pengguna non-teknis.
                </p>
                <ul className="space-y-4">
                  {benefits.map((benefit, index) => (
                    <BlurFade key={index} delay={0.5 + index * 0.1} inView>
                      <li className="flex items-center space-x-3">
                        <CheckCircle className="h-5 w-5 text-primary flex-shrink-0" />
                        <span>{benefit}</span>
                      </li>
                    </BlurFade>
                  ))}
                </ul>
              </div>
            </BlurFade>
            <BlurFade delay={0.75} inView>
              <div className="relative">
                <Card className="p-8">
                  <div className="text-center">
                    <img src="/logo.svg" alt="Vulnity Logo" className="h-20 w-20 mx-auto mb-4" />
                    <h3 className="text-xl font-semibold mb-2">
                      Penelitian & Pengembangan
                    </h3>
                    <p className="text-muted-foreground">
                      Proyek penelitian yang dikembangkan menggunakan metode Research and
                      Development (R&D) dengan pendekatan Waterfall untuk pembelajaran
                      sistematis pengembangan perangkat lunak keamanan.
                    </p>
                  </div>
                </Card>
              </div>
            </BlurFade>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 bg-primary text-primary-foreground">
        <div className="container mx-auto text-center">
          <BlurFade delay={0.25} inView>
            <h2 className="text-3xl font-bold mb-4">
              Jelajahi Prototipe Vulnity
            </h2>
          </BlurFade>
          <BlurFade delay={0.5} inView>
            <p className="text-xl mb-8 opacity-90">
              Eksplorasi prototipe web vulnerability scanner untuk pembelajaran deteksi
              kerentanan SQL Injection dan XSS dalam lingkungan penelitian.
            </p>
          </BlurFade>
          <BlurFade delay={0.75} inView>
            <Link to="/register">
              <Button size="lg" variant="secondary">
                Mulai Eksplorasi
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
          </BlurFade>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t py-8 px-4">
        <div className="container mx-auto text-center text-muted-foreground">
          <BlurFade delay={0.25} inView>
            <p>&copy; 2025 Vulnity. Prototipe Web Vulnerability Scanner untuk Pembelajaran Keamanan Web.</p>
          </BlurFade>
        </div>
      </footer>
    </div>
  )
}
