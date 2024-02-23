#Vu Dinh Tri
#01.01.2024
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
external-controller: '127.0.0.1:9090'
dns:
  enable: true
  ipv6: false
  default-nameserver: null
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  nameserver: null
  fallback:
    - 'https://doh.dns.sb/dns-query'
    - 'https://dns.cloudflare.com/dns-query'
    - 'https://dns.twnic.tw/dns-query'
    - 'tls://8.8.4.4:853'
  fallback-filter:
    geoip: true
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/32
proxies:
proxy-groups:
  - name: 🅸🅽🆃🅴🆁🅽🅴🆃
    type: select
    proxies:
      - 🄻🄾🄰🄳 🅱🅰🅻🅰🅽🅲🅴
      - 🄻🄾🄰🄳 🆅🅽🅰🅼
      - 🄰🅄🅃🄾 🅰🅻🅻
      - 🄰🅄🅃🄾 🆅🅽
      - 🄰🅄🅃🄾 🆂🅸🅽🅶
      - 🄰🅄🅃🄾 🅷🅺
      - 🄰🄳🅂 🅱🅻🅾🅲🅺
      - DIRECT
    use:
      - VPN
    include-all: null
    use-url: null
    icon: https://cdn1.iconfinder.com/data/icons/ionicons-fill-vol-2/512/power-1024.png
    #'https://cdn2.iconfinder.com/data/icons/network-and-internet-3d-illustration-pack/512/5G_3D_Illustration_Icon.png'
    ssid-policy:
      cellular: 🄰🅄🅃🄾 🆅🅽
      default: DIRECT
      wifi: DIRECT
  - name: 🄻🄾🄰🄳 🅱🅰🅻🅰🅽🅲🅴
    type: load-balance
    use:
      - VPN
    icon: https://cdn3.iconfinder.com/data/icons/aami-web-internet/64/aami8-15-1024.png
    hidden: null
  - filter: '🇻🇳'
    name: 🄻🄾🄰🄳 🆅🅽🅰🅼
    type: load-balance
    icon: https://cdn4.iconfinder.com/data/icons/outline-circular-world-flags/37/247-VNM--Viet_Nam-1024.png
    use:
      - VPN
  - name: 🄰🅄🅃🄾 🅰🅻🅻
    type: url-test
    proxies: null
    url: 'http://www.gstatic.com/generate_204'
    interval: 180
    hidden: null
    use-url: null
    icon: 'https://cdn2.iconfinder.com/data/icons/audio-music-1/48/27-1024.png'
    use:
      - VPN
  - name: 🄰🅄🅃🄾 🆅🅽
    type: url-test
    proxies: null
    url: 'http://www.gstatic.com/generate_204'
    interval: 180
    hidden: null
    use-url: null
    icon: 'https://cdn4.iconfinder.com/data/icons/outline-circular-world-flags/37/247-VNM--Viet_Nam-1024.png'
    use:
      - VPN
    filter: '🇻🇳'
  - name: 🄰🅄🅃🄾 🆂🅸🅽🅶
    type: url-test
    proxies: null
    url: 'http://www.gstatic.com/generate_204'
    interval: 180
    hidden: null
    use-url: null
    icon: 'https://cdn3.iconfinder.com/data/icons/international-circle-flags-outline/480/singapore-singaporean-asian-country-flag-1024.png'
    use:
      - VPN
    filter: '🇸🇬'
  - name: 🄰🅄🅃🄾 🅷🅺
    type: url-test
    proxies: null
    url: 'http://www.gstatic.com/generate_204'
    interval: 180
    hidden: true
    use-url: null
    icon: 'https://cdn3.iconfinder.com/data/icons/international-circle-flags-outline/480/hong-kong-asian-country-flag-1024.png'
    use:
      - VPN
    filter: '🇭🇰'
  - filter: 'AdBlock'
    name: 🄰🄳🅂 🅱🅻🅾🅲🅺
    type: url-test
    use:
      - VPN
    hidden: null
    icon: https://cdn1.iconfinder.com/data/icons/seo-markiting/66/38-1024.png
    include-all: true
  - name: 🅰🅳🆂
    proxies:
      - DIRECT
      - REJECT
    type: select
    icon: https://cdn4.iconfinder.com/data/icons/233-internet-browser-for-web-sites-and-secure-surf/64/blocker_block_shield_hand_stop_adblock_advertising_website_device-1024.png
rules:
 
  - RULE-SET,ADSBLOCK,🅰🅳🆂
  - MATCH,🅸🅽🆃🅴🆁🅽🅴🆃
rule-providers:
  ADSBLOCK:
    behavior: domain
    format: text
    interval: 0
    url: 'https://raw.githubusercontent.com/DrStrangeVN/Stash/main/Rule_Allserver.js'
  
http:
  mitm:
    - "-redirector*.googlevideo.com"
    - "youtubei.googleapis.com"
    - "*.googlevideo.com"
    - "www.youtube.com"
    - "s.youtube.com"
    - "youtubei.googleapis.com"
    - "mobile-api.adguard.org"
  script:
    - match: ^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next)\?
      name: YouTubeAds
      type: response
      require-body: true
      timeout: 30
      binary-mode: true
      max-size: 2097152
    - match: ^https?:\/\/mobile-api\.adguard\.org\/api\/.+\/ios_validate_receipt
      name: AdGuard
      type: response
      require-body: true
      timeout: 10

  rewrite:
    - (^https?:\/\/[\w-]+\.googlevideo\.com\/(?!dclk_video_ads).+?)&ctier=L(&.+?),ctier,(.+) $1$2$3 302
    - ^https?:\/\/[\w-]+\.googlevideo\.com\/(?!(dclk_video_ads|videoplayback\?)).+&oad - reject-200
    - ^https?:\/\/(www|s)\.youtube\.com\/api\/stats\/ads - reject-200
    - ^https?:\/\/(www|s)\.youtube\.com\/(pagead|ptracking) - reject-200
    - ^https?:\/\/s\.youtube\.com\/api\/stats\/qoe\?adcontext - reject-200
script-providers:
  YouTubeAds:
    url: https://raw.githubusercontent.com/app2smile/rules/master/js/youtube.js
    interval: 86400
  AdGuard:
    url: https://github.com/lonely0811/olsd/raw/main/ad.js
    interval: 86400
tiles:
  - name: IP
    interval: 86400
    script-providers:
    IP:
    url: https://raw.githubusercontent.com/DrStrangeVN/Stash/main/IP.js
    interval: 86400
proxy-providers:
  VPN:
    interval: 7200
    url: xxxx
ssid-policy:
  wifi: DIRECT
  cellular: 🄰🅄🅃🄾 🆅🅽
  default: 🅸🅽🆃🅴🆁🅽🅴🆃
