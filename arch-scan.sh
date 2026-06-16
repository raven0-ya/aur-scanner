#!/usr/bin/env bash
#
# arch-scan.sh - Arch Linux Security Scanner
# Scans installed and AUR packages for signs of compromise.
#
# Features:
#   1. Checks installed packages against known compromised package lists
#   2. Verifies package file integrity via pacman -Qkk
#   3. Scans for malware indicators: eBPF rootkit, systemd persistence,
#      malicious npm/bun packages, suspicious SUID binaries
#   4. Scans AUR PKGBUILDs for suspicious patterns
#   5. Checks system for anomalies (cron, services, network)
#
# License: MIT

set -euo pipefail

VERSION="1.0.1"

# ---------------------------------------------------------------------------
# Configuration & Signatures
# ---------------------------------------------------------------------------

# Remote package list sources (reliable, community-maintained)
REMOTE_LISTS=(
    "https://md.archlinux.org/s/SxbqukK6IA/download"
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt"
    "https://cscs.pastes.sh/raw/aurvulnlist20260611.txt"
)

# Known malicious npm package names (from the June 2026 atomic-lockfile campaign)
MALICIOUS_NPM_PACKAGES=(
    "atomic-lockfile"
    "lockfile-js"
    "js-digest"
)

# Known attacker account names
ATTACKER_ACCOUNTS=(
    "krisztinavarga" "franziskaweber" "tobiaswesterburg" "ellenmyklebust"
    "custodiatovar" "veramagalhaes" "laurentbavaud" "vitoriapires"
    "catringiess" "dominikgross" "meryemplath" "atomicwalllet"
    "atomicwalet" "exodas" "exoduz" "exodys" "exodis" "exodud"
    "exouds" "exodux" "exoduss" "skarbricat" "ivonahruskova"
    "simongeisler" "arojas"
)

# Refined patterns to scan in AUR PKGBUILDs (.install) to reduce false positives
SUSPICIOUS_PATTERNS=(
    "curl.*|.*bash"
    "bash.*<.*curl"
    "wget.*|.*bash"
    "eval.*\$(curl"
    "eval.*\$(wget"
    "base64.*-d.*|.*bash"
    "base64.*-d.*sh"
    "python.*reverse_shell"
    "nc .*-e "
    "ncat .*-e "
    "/dev/tcp/"
    "rm -rf /etc"
    "dd if=/dev/zero of=/dev/sd"
    "mkfs\.ext[234].*/dev/"
    ":\(\){.*:\(\)"
    "authorized_keys"
    "chmod u+s "
    "chmod 4755"
    "npm install atomic-lockfile"
    "npm install lockfile-js"
    "npm install js-digest"
    "bun install atomic-lockfile"
    "bun add js-digest"
    "bun install js-digest"
    "curl.*temp.sh"
    "wallet_seed|private_key|upload.*wallet"
    "\.onion"
    "crontab.*-e|echo.*>.*cron"
    "systemctl.*enable"
    "Restart=always"
    "pkill -9"
)

# CRITICAL FIX: Embedded fallback list moved to the top
# Bash evaluates line-by-line; it must be defined before functions call it.[cite: 1]
EMBEDDED_LIST=(
123pan-bin 1code 8188eu-dkms 8192eu-dkms-git abntex acpitool actual-ai
adapta-gtk-theme-git adblock2privoxy adsuck aion-git akira-git akonadi-git
aksusbd albion-online-launcher-bin alfonz alienfx alienfx-lite alock-git
alternating-layouts-git alttab-git alvr ambiance-radiance-colors-suite
amdgpu-fancontrol-git amdguid-wayland-bin amideamtterm amule-dlp-git
android-backup-extractor android-docs android-google-play-apk-expansion
android-google-play-licensing androidscreencast-bin android-signapk
android-signapk-gui android-support-repository annobin ansible-language-server
ant-dracula-gtk-theme antfs-cli-git antechamber antileech anythingllm-appimage
anythingllm-cli-bin apache-ant-contrib apk-installer-gui apm_planner-bin
apothem apple-music-desktop apwal aquaria-ose arachnophilia arcadia archivemail
archjh archlinux-themes-balou archlinux-themes-slim archmage arch-palemoon-search
archtex-git arch-update-va arduino-git argouml aria2fear ang-allinone
arm-linux-gnueabihf-binutils arm-linux-gnueabihf-glibc-headers
arm-linux-gnueabihf-linux-api-headers ar-smileys artanis-git ascii-rain-git
asciiworld-git astah-uml astro-editor-appimage asus-fan-dkms-git atlassian-confluence
atlassian-plugin-sdk atolm-openbox-theme atomicwalet atomicwalllet audible-activator-git
audiere audiotube-git auryo autohand-cli autolabel autolatex autologin autozen
avarice-git avogadro2-git avra awesome-cinnamon awesome-revelation-git awoken-icons
aws-cli-git aws-sam-cli azurlaneautoscript backup2l backwild balena-cli barrier-git
batman-adv bazel-buildtools bbswitch-git bcalc bcnc bdf-creep beancount-git beebee
beef beets-copyartifacts-git binnavi biosdevname bitcoin-core-git blackfire-agent 
blender-plugin-vectex bleufear-gtk-theme blinkenlib blogc blt blueprint-compiler-git 
blueproximity-py3-git booklore boostnote-bin borg-git bouml bpytop-git bracket 
brightness-controller-git brother-hl3150cdw brother-hll6200dw brow6el brow6el-git 
brscan3 bsnes-plus-git burn-cd caelum camotics canon-pixma-mg3000-complete-fixed 
capt-src capture cardano-node cartridge-cli castawesome castersoundboard-git cattle 
cavestory+-hb cb2bib ccase-bin ccccccl-git ccminer-git ccsm-gtk3 centerim5-git 
cerbere-git cerebro cgminer c++-gtk-utils-gtk2 cgvg charcoal chexquest3-wad 
chez-scheme-git chipmachine chipmunk chisel chromeos-apk-git cinny-desktop-system-tray 
cint cjs-git claic lamfs clang15 clang19 clash-m clevo-xsm-wmi cling-git clipgrab-kde 
cmake-modules-webos-git cmospwd cmuclmtk cnijfilter-common cnijfilter-common-mg5400 
cnijfilter-ip110 cnijfilter-mp550 codeclimate code-git codeigniter codenomad-bin 
codeql-cli-bin coffeescript-git cogpit-bin colorhug-client colorsvn colorz compiler-rt19 
compizconfig-python compizconfig-python-git compiz-fusion-plugins-experimental 
compiz-fusion-plugins-experimental-git compiz-fusion-plugins-extra 
compiz-fusion-plugins-extra-git complexity connman-ncurses connman-ncurses-git 
connman-ui-git containerd-git contemporary-cursors controllermap coolreader coolreader3-git 
coppeliasim-bin cowdancer coyim cpp-netlib cppreference-devhelp cpufreqd cpuminer-multi 
cpuminer-multi-git cpu-monitor-extension-lxpanel-plugin cpuset craftbukkit-plugin-worldedit 
createvm cross-mingw-w64-gdb cryptowatch-desktop-bin cubieboard-livesuit cura 
cura-plugin-octoprint-git curecoin-qt-git curseradio-git cutefish-calculator cutefish-core 
cutefish-dock cutefish-filemanager cutefish-icons cutefish-launcher cutefish-qt-plugins 
cutefish-screenlocker cutefish-screenshot cutefish-settings cutefish-statusbar 
cutefish-wallpapers cutemarked-git cvs2svn cvs-feature-bin cwiid cynthiune.app d1x-rebirth 
daala-git daggerfall-addons dagu-bin dahdi-linux dalbum darwinia dashcore datatype99 
davtools dbxcli deepin-mail-bin deepin-wine6-stable deheader delaycut denaro depot 
desktopnova dexed-ide-bin dfhack dfhack-bin dh-python dianara dibuja difi difi-bin 
digikam-without-akonadi digitemp distrho-ports-lv2-git dkopp dmg2dirdocker-gc-git doctoc 
doom3-inhell doomsday dot-git dots-hyprland-fork-git dptf drascula drbl-experimental 
drm_tools droopy-git dropbox-kde-systray-icons dsd dsdcc-git dub-git dukto dvbcut dvdrip 
dvorak7min dyad-bin dynamod e4rat-lite-git easymp3gain-qt4-bin easy_spice easytag-git 
echinus-git echo-icon-theme-git eclipse-checkstyle eclipse-i18n-de eclipse-i18n-fr 
eclipse-markdown edconv-bin edx-downloader-git eel-language efiboots-git eiskaltdcpp 
electrum-bin electrum-nmc elmerfem elm-format-bin elm-platform emacs-color-theme 
emacs-d-mode emacs-ess-git emacs-find-recursive emacs-icicles emacs-identica-mode 
emacs-jabber emacs-jabber-git emacs-magit emacs-mew emacs-mmm-mode emacs-paredit 
emacs-pkgbuild-mode-git emacs-popup-el emacs-sml-mode emacs-yasnippet-git emms-git 
encryptr energyplus envoy-git envy-pn-font eperiodique epson-inkjet-printer-escpr2-clos-bin 
errut eslint-plugin-react etherpad-lite etm eviacam evilvte-git evilwm evopedia-git 
evopop-gtk-theme evopop-icon-theme exact-image exiftag exodas exodis exodud exodus 
exoduswallet exodus-wallet-bin exodux exoduz exodys exouds fanicontrol fantom farmmod-hub 
fasd-git fastjet fastoggene fatx fbctrl fbff-git fcitx5-pinyin-sougou-dict-git 
fcitx-baidupinyin fengoffice ffdiaporama-texturemate ffmpeg3.4 ffmpeg-bitrate-stats 
ffmpeg-quality-metrics fifth filebot47 findpkg-git firebird firefox-extension-adnauseam-bin-am 
firmium-desktop-git firmware-mod-kit fisher-git fishui fishui-git flashfocus flatcam-git 
flexiblas flow flowblade-git flow-pomodoro flv2x264 flynarwhal fmlib fontweak forgecode-bin 
formidable-bin fortune-mod-firefly fpp-git frame freemind-git freeter frutool fs2-knossos 
fs2_open-mediavps fspy fstar-git ft232r_prog ftl fuego-svn fuel fusion-icon fusion-icon-git 
futhark-bin fwlogwatch g2 g3data gahshomar galaxy2 ganyremote garmindev gavrasm gcal 
gcccpuopt gcstar gcstar-gitlab gdl gdlmm gecode geekcode geforcenow-electron gemistdownload 
get_flash_videos getlive gfxbench ggobangimp-plugin-arrow gist-git gisto git-annex-standalone 
gitflow-avh git-flow-completion-git gitfs gitinspector gitosis-git git-remote-hg-git gitsogitter-bin 
gkrellm gle-graphics globalplatform globalprotect-bin glosstex glsl-debugger-git gmp4 gmt-coast 
gmt-cpt-city gnato gnome-battery-bench-git gnome-contacts-git gnome-directory-thumbnailer 
gnome-pass-search-provider-git gnome-randr-rust gnome-rdp gnome-shell-extension-cpufreq-git 
gnome-shell-extension-dynamic-top-bar gnome-shell-extension-hibernate-status-git 
gnome-shell-extension-topicons-plus gnome-shell-extension-transmission-daemon-git 
gnome-shell-extension-x11gestures gnome-shell-theme-arc-clearly-dark-git gnome-specimen 
gnome-terminal-fedora gnome-usage-git gnome-xcf-thumbnailer gnuplot-git gnutls3.8.9 gogs-git 
gog-the-witcher-2-assassins-of-kings gohufont-powerline gopenvpn-git gopher2600 gopher2600-bin 
goqat gosh gpicsync gpshell gpx-viewer graal-bin graveman greenisland green-tunnel-bin greetd-wl 
greet-git gridmgr-git grim-git gr-osmosdr-git grpn grub4dos grub-luks-keyfile 
gsettings-desktop-schemas-git gtkimageview gtksetpwc gtk-theme-bsm-simple gtk-theme-metagrip 
gtk-theme-windows10-dark gtk-vnc-gtk2 guake-colors-solarized-git guile-git guile-reader guile-ssh 
guiscrcpy gummy gummy-git gxemul hackmatrix-git halberdha-pacemaker-git hardcode-tray harminv 
harmony-wad haskell-asn1-data haskell-chart haskell-failure haskell-hscurses haskell-hssyck 
hattrick_organizer haunthaxe-git hd2u hdx-512-git headphones hearthstone-linux-gui-appimage 
hearthstone-linux-gui-bin hepmc2 hexchat-otr hfstospell hifive1-sdk-git hister-git hnswlib-git 
homeassistant-osagent homeassistant-supervised hop horst hotlinemiami howm-x11-git hpgcc hp-health 
hpoj htdig top-vim-solarized-git httpry huawei-stat-e220 hunter hydownloader-git hydrapaper-git 
hydrus-git hypervc-qt4 hypr i2c-ch341-dkms i3bar-river i3-gnome-git i3lock-fancy-dualmonitors-git 
ianny-bin ibci bm-sw-tpm2 ibus-uniemoji-git icdiff-git ice-ssb ideviceinstaller-git 
ifcopenshell-git igdm ihaskell-git ike ikiosk imageglass img2djvu-git inadyn inadyn-mt 
indicator-session infinity-background infnoise-openssl-git inform7 inkslides-git intelmetool-git 
intelpwm-udev interface99 ios-webkit-debug-proxy ipfs-desktop-bin ipsw iptrafvol iron-heart-git 
irssistats isight-firmware-tools itop j4-make-config-git ja2-stracciatella-git jasmin jasp-desktop 
java-berkeleydb java-flexdock javahelp2 java-qdox jd-gui jdk11-openj9-bin jdk17-jetbrains-bin 
jdk8-graalvm-bin jdk-openj9-bin jetbrains-mps jflex jinxijo joy joycon-git joymouse jreen-git 
jstock jzip k3sup k4dirstat kalu-git kapacitor kapidox-git katrainkdb kddockwidgets-git 
kdevelop-pg-qt-git keepass keepass-fr keepass-plugin-qualitycolumn keepassx2 keeperrl-git 
kexi kicad-library-ab2-git kiconedit kimageformats-git kio_gopher kiss kmarkdownwebview 
kodi-addon-inputstream-adaptive-git kokua-secondlife kompare-git kookbook kopano-core koules 
kproperty krakatau-git kreport kteatime kubo-git kvirc-git kwin-effects-blur-respect-rounded-decorations-git 
kwin-scripts-quarter-tiling-git kwplayer lab-bin ladish laditoolslash lastfmlib latex-digsig 
latex-make latex-mk lazylpsolverlibs-git lbench ledger-udev-bin legofy-git leocad-git lesstif 
flexmark_pro700 lib32-egl-wayland lib32-fftw lib32-freeimage lib32-gimp lib32-gnome-themes-extra 
lib32-graphene lib32-libfmod lib32-libjson lib32-libmad lib32-libreplaygain lib32-libxpm 
lib32-libxxf86dga lib32-mtdev lib32-tk libafterimage libarcus-git libbobcat libcompizconfig-git 
libcss-git libcutefish libdill libdivecomputer-git libevdevc libffi-static libfprint-vfs_proprietary-git 
libfreenect-git libgdata libgtkhtml libhugetlbfs libisl15 libjxl-noglycin libkarma libkdcraw-git 
libkomparediff2-git libmrss libnbcompat libntru libnxm libopenaptx-git libprelude libptp2 
libpurple-carbons-git libpurple-lurch-git libpurple-meanwhile libpuzzle libquvi libquvi-scripts 
libreoffice-extension-coooder libreplibrep-git libretro-hatari-enhanced-git libretro-mame-git 
libretro-mednafen-supergrafx-git libsmi libspatialindex-git libtcd libtrash libuiohook libviper 
libwapcaplet-git libxaw3dxft libxdi libxml-ruby libyami lightdm-webkit-theme-userdock lilypond-git 
limbo-hi limesuite-git linkerd linphone-desktop-all linphone-desktop-all-git 
linphone-plugin-msx264 linux-bcachefs-git linux-cachyos-deckify-native 
linux-cachyos-deckify-native-headers linux-cachyos-native linux-cachyos-native-headers 
linux-cachyos-native-nvidia-open linux-cachyos-rc-native linux-cachyos-rc-native-headers 
linux-cachyos-rc-native-nvidia-open linux_logo_archcustom linux-manjaro-xanmod linux-rc linux-tool 
linux-xanmod-rog linvst liri-cmake-shared-git liri-shell-git litell llvm-cbe-git 
lorem-ipsum-generator love09 lowfi-bin lrexlib-pcre5.1 ls++ lsx lttng-modules lua51-sql-sqlite 
luazip5.1 lucidvideo luksipc-git lurelv lxdvdrip m5rcode machinarium mac-os-lion-cursors 
madsonic magicassistant-gtk magpie-wm make-3.81 mako-center-git manuskript mapbox-studio 
marcfs-git markmywords-git marytts maszyna-git mathsat-5 mato-icons-git matrixbrandy maxima-git 
mbm-gpsd pl4nkton-git mcpatcher mcp-probe mc-skin modarin-debian me_cleaner-git menumaker-compiz 
mermaid-ascii-git mermark-edit mesa-dlss-reflex-git mesecons-git mesos meteomic tray mikidown-git 
milena milena-datamilton-git mime-archpkg mimic-node-git minecraft-overviewer 
minecraft-overviewer-git minergate-cli mingw-w64-adwaita-icon-theme mingw-w64-geos 
mingw-w64-gtk2 mingw-w64-libcroco mingw-w64-libidn mingw-w64-libsndfile mingw-w64-pcre 
mingw-w64-sdl mingw-w64-sdl2_ttf minimax-bin-hardened miniongg minitube miro-video-converter 
mirrorlist-rankmirrors-hook misuzu-music-bin mkgmap-svn mmc-utils-git mobac-svn mon2cam-git 
mongo-cxx-driver-legacy-0.0-26compat mono-addins monochrome monochrome-git montecarlo-font 
moonshine moor-git mopen mopidy-moped mopidy-youtube mount-gtk movgrab mp3guessenc mpirmqttfx-bin 
msie ms-office-online multimon-ng-git multiwinia mxnet mysqltuner-git mythes-cs n1-translator 
naemon naemon-livestatus natapp nautilus-folder-icons nautilus-git nautilus-mediainfo 
nautilus-renamer ncl ncursesfm-git ndyndns nebuchadnezzar-git necpp-git nemerle neochat-git 
neovim-autopairs-git neovim-gtk-git neovim-nvim-treesitter nerf-pine netmenu netmon-git netrik 
networkmanager-dispatcher-pdnsd networkmanager-ssh-git neuro-karaoke-wrapper-git 
neuron-zettelkasten-bin neuropolitical-ttf new-api-privacy-filter new-api-privacy-filter-git 
nextcloud-app-audioplayer nextcloud-app-facerecognition nextcloud-app-gpoddersync 
nextcloud-app-integration-google nextcloud-app-repod nextcloud-app-twofactor-gateway nextcloud-git 
nexus-bin nginx-mod-vts nhentai-git nheqminer-cuda-git nikki nikola-git nip2 nixnote2 
nixnote2-git n-ninja nocodb noctyra-dotfiles-git noctyra-meta-git nodejs-elm nodejs-forever 
nodejs-how2 nodejs-ionic nodejs-jsdoc nodejs-webpack non-daw-git nordnm notepad---bin 
notify-desktop-git notion-app-enhanced nox-bin nrpe numix-gtk-theme numix-themes-electric 
numix-themes-green num-utils nvdock-bumblebee nvidia-xrun-git nwchem nwchem-bin nx3-all 
ob-xdocaml-lambda-term ocaml-sexplib ocaml-typerex ocaml-xmlm oclint octave-hgoctave-miscellaneous 
octocode ohcount ohcount-git oh-my-git olivia-git openav-sorcer-git open-axiom 
opencode-codebase-index-bin opencorsairlink-git opendrop openhab2 openhab3 open-hexagon-git 
openms openmsx-catapult opennebula openpyn-nordvpn openstego openui5 openxray opl-synth 
optimizevideo-git oracle-bin organize-bin orientdb-community osmose osvr-libfunctionality-git 
otf-inconsolata-g-powerline-git otf-sauce-code-powerline-git ovras owncloud-client-git 
oxefmsynth oxygen-gtk3-git pacforge pacgem panopticon-git pantheon-applications-menu-git 
pantheon-print-git pantheon-session-git pantum-driver paper-desktop-bin papirus-color-scheme 
papirus-maia-icon-theme-git paq8o parallel-python pass-clipb-for-desktop pbincli pb2gcode pcsxr-git 
pdf2book pdf4qt-git pdi-cepee pdf pelican-git pem-micro python2-suds python2-virtualenv 
python2-xdg python2-xlrd python2-xlwt python2-yenc python2-zc-buildout python2-zope-interface 
python3-saml python-aioice python-aiogithubapi python-aiosmtplib python-airtouch4py python-aoch 
python-ase python-async-upnp-client python-autovivification python-av python-awscrt python-awswrangler 
python-babelfont python-bandit python-bankclient python-base58 python-bcdoc python-bech32 
python-bellows python-bereal python-bidict python-binaryornot python-bitcoinlib python-bitstring 
python-bitstruct python-blendmodes python-boltons python-boolean.py python-bootstrapform 
python-bottle python-braceexpand python-btrees python-bubblepy python-bugout python-build 
python-cached-property python-cachecontrol python-can python-capman python-cattrs 
python-cbor2 python-ccxt python-ceed python-celery python-cfg python-cfn-flip python-chacha20 
python-chacha20poly1305 python-chai python-chardet python-checkpy python-cheetah python-ciscoconfparse 
python-ciso8601 python-clapper python-click-didyoumean python-click-help-colors 
python-click-log python-click-repl python-click-thread python-cligj python-cloudant 
python-cloudflare python-cloup python-cmarkgfm python-cmdstanpy python-cobblestone 
python-codespell python-colorcet python-colored python-colorlog python-colormap 
python-colorspacious python-colour python-commonmark python-compath python-compreffor 
python-concurrent-log-handler python-confget python-configargparse python-confuse 
python-contextlib2 python-contextvars python-cookiecutter python-coolname python-copr 
python-corner python-cpuinfo python-cram python-pylint python-pyls python-pyls-black 
python-pyls-isort python-pyls-mypy python-pyls-spyder python-pynest2d python-pyocd 
python-pyocr python-pyodbc python-pyopencl python-pyorbital python-pyosf python-pypandoc 
python-pypandoc_binary python-pypcap python-pypdf python-pypdf2 python-pypillowfight 
python-pypromise python-pyprind python-pyproj python-pyproject-hooks python-pypsrp 
python-pypump python-pyramid python-pyramid-jinja2 python-pyramid-mako python-pyramid-tm 
python-pyrasite python-pyreader python-pyreadstat python-pyrect python-pyresample 
python-pyRFC3339 python-pyro-ppl python-pyroute2 python-pyrsistent python-pysaml2 
python-pyshark python-pyshp python-pyside python-pyside2 python-pysmi python-pysnmp 
python-pysnmp-lextudio python-pysocks python-pysolr python-pysparse python-pyspellchecker 
python-pystemd python-pysvn python-pytables python-pytaglib python-pytba python-pytest 
python-pytest-aiohttp python-pytest-arraydiff python-pytest-astropy python-pytest-astropy-header 
python-pytest-benchmark python-pytest-binder python-pytest-black python-pytest-bq 
python-pytest-cases python-pytest-check python-pytest-cov python-pytest-datafixtures 
python-pytest-dependency python-pytest-describe python-pytest-django python-pytest-djangoapp 
python-pytest-doctestplus python-pytest-env python-pytest-envfiles python-pytest-examples 
python-pytest-filter-subpackage python-pytest-flake8 python-pytest-flask python-pytest-flask-sqlalchemy 
python-pytest-freezegun python-pytest-forked python-pytest-html python-pytest-httpserver 
python-pytest-incremental python-pytest-instafail python-pytest-isort python-pytest-jsonschema 
python-pytest-lazy-fixture python-pytest-localserver python-pytest-logdog python-pytest-logging 
python-pytest-mock python-pytest-mock-api python-pytest-mpl python-pytest-multihost 
python-pytest-mypy python-pytest-mypy-plugins python-pytest-ordering python-pytest-param 
python-pytest-pikachu python-pytest-pycodestyle python-pytest-pylint python-pytest-raises 
)

# Configuration flags[cite: 1]
USE_REMOTE=true
CHECK_INTEGRITY=false
DEEP_SCAN=false
FULL_SCAN=false
VERBOSE=false
HELP=false

# Temp files[cite: 1]
TEMP_DIR=""
LIST_FILE=""

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

cleanup() {
    [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
}

error() { echo "[ERROR] $*" >&2; }
warn()  { echo "[WARN] $*" >&2; }
info()  { echo "[INFO] $*"; }
verbose() { $VERBOSE && echo "[DEBUG] $*" || true; }

check_cmd() {
    command -v "$1" >/dev/null 2>&1 || { warn "Required command '$1' not found"; return 1; }
}

print_banner() {
    echo "============================================================"
    echo "  arch-scan.sh v${VERSION} - Arch Linux Security Scanner"
    echo "  Scans installed/AUR packages for signs of compromise"
    echo "============================================================"
    echo
}

print_separator() {
    echo "------------------------------------------------------------"
}

# ---------------------------------------------------------------------------
# Phase 1: Fetch and merge known compromised package lists
# ---------------------------------------------------------------------------

fetch_package_lists() {
    local merged_file="$1"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    if ! $USE_REMOTE; then
        info "Remote fetch disabled. Using embedded fallback list."
        printf '%s\n' "${EMBEDDED_LIST[@]}" > "$merged_file"
        rm -rf "$tmp_dir"
        return 0
    fi

    if ! check_cmd curl; then
        warn "curl not found. Using embedded fallback list."
        printf '%s\n' "${EMBEDDED_LIST[@]}" > "$merged_file"
        rm -rf "$tmp_dir"
        return 0
    fi

    local fetched_any=false
    local all_pkgs=()

    for url in "${REMOTE_LISTS[@]}"; do
        verbose "Fetching: $url"
        local out_file="$tmp_dir/$(basename "$url" | sed 's/[^a-zA-Z0-9._-]/_/g')"
        if curl -fsSL --max-time 15 --proto '=https' "$url" > "$out_file" 2>/dev/null; then
            local count
            count=$(grep -cE '^[a-z0-9][a-z0-9._+\-]*[a-z0-9+]$' "$out_file" 2>/dev/null || echo 0)
            if [[ "$count" -gt 0 ]]; then
                verbose "  Got $count packages from $(basename "$url")"
                mapfile -t pkgs < <(grep -E '^[a-z0-9][a-z0-9._+\-]*[a-z0-9+]$' "$out_file")
                all_pkgs+=("${pkgs[@]}")
                fetched_any=true
            else
                verbose "  No valid packages in $(basename "$url")"
            fi
        else
            verbose "  Failed to fetch $url"
        fi
    done

    if ! $fetched_any; then
        warn "Could not fetch any remote lists. Using embedded fallback."
        printf '%s\n' "${EMBEDDED_LIST[@]}" > "$merged_file"
    else
        printf "%s\n" "${all_pkgs[@]}" | sort -u > "$merged_file"
        local total
        total=$(wc -l < "$merged_file")
        info "Loaded $total known compromised packages from remote sources."
    fi

    rm -rf "$tmp_dir"
}

# ---------------------------------------------------------------------------
# Phase 2: Check installed packages against known compromised list
# ---------------------------------------------------------------------------

check_installed_against_list() {
    local list_file="$1"
    local exit_code=0
    print_separator
    echo " [1] Checking installed packages against known compromised list"
    print_separator

    if ! check_cmd pacman; then
        error "pacman not found. Is this Arch Linux?"
        return 1
    fi

    # Check AUR packages (foreign)
    if pacman -Qqm >/dev/null 2>&1; then
        local aur_hits=()
        while IFS= read -r pkg; do
            if grep -Fxq "$pkg" "$list_file" 2>/dev/null; then
                aur_hits+=("$pkg")
            fi
        done < <(pacman -Qqm 2>/dev/null)

        if [[ ${#aur_hits[@]} -gt 0 ]]; then
            warn "Found ${#aur_hits[@]} known compromised AUR package(s) installed:"
            for pkg in "${aur_hits[@]}"; do
                local ver date
                ver=$(pacman -Qi "$pkg" 2>/dev/null | awk -F': ' '/^Version/ {print $2}')
                date=$(pacman -Qi "$pkg" 2>/dev/null | awk -F': ' '/^Install Date/ {print $2}')
                echo "    $pkg (version: $ver, installed: $date)" >&2
            done
            exit_code=2
        else
            info "No known compromised AUR packages installed."
        fi
    fi

    # Also check all installed packages
    local all_hits=()
    while IFS= read -r pkg; do
        if grep -Fxq "$pkg" "$list_file" 2>/dev/null; then
            all_hits+=("$pkg")
        fi
    done < <(pacman -Qq 2>/dev/null)

    local total_count
    total_count=$(pacman -Qq 2>/dev/null | wc -l)
    local foreign_count
    foreign_count=$(pacman -Qqm 2>/dev/null | wc -l)
    local list_count
    list_count=$(wc -l < "$list_file")

    info "Scanned $total_count installed packages ($foreign_count AUR) against $list_count known compromised."
    return $exit_code
}

# ---------------------------------------------------------------------------
# Phase 3: Package file integrity check
# ---------------------------------------------------------------------------

check_integrity() {
    local exit_code=0
    print_separator
    echo " [2] Package file integrity check (pacman -Qkk)"
    print_separator

    if ! check_cmd pacman; then
        return 1
    fi

    local tmpfile
    tmpfile=$(mktemp)

    info "Checking all installed package file integrity..."
    info "This may take a while. Only packages with warnings are shown."

    if pacman -Qkk 2>/dev/null > "$tmpfile"; then
        info "All packages pass integrity check."
    else
        local warnings
        warnings=$(grep -i "warning\|error\|missing\|modified" "$tmpfile" | head -50 || true)
        if [[ -n "$warnings" ]]; then
            warn "Package integrity warnings found:"
            while IFS= read -r line; do
                echo "    $line" >&2
            done <<< "$warnings"
            exit_code=2
        fi
    fi

    rm -f "$tmpfile"
    return $exit_code
}

# ---------------------------------------------------------------------------
# Phase 4: Malware indicator scan
# ---------------------------------------------------------------------------

check_ebpf_rootkit() {
    local exit_code=0
    echo " [3.1] eBPF rootkit check"
    echo "  Checking for hidden BPF maps in /sys/fs/bpf/..."

    if [[ ! -d /sys/fs/bpf ]]; then
        echo "    /sys/fs/bpf not accessible (BPF filesystem not mounted or no permissions)."
        echo "    Run with sudo to check for hidden BPF maps."
        return 0
    fi

    local found=()
    for map in hidden_pids hidden_names hidden_inodes; do
        if [[ -e "/sys/fs/bpf/$map" ]]; then
            found+=("$map")
        fi
    done

    if [[ ${#found[@]} -gt 0 ]]; then
        warn "eBPF rootkit indicators found:"
        for m in "${found[@]}"; do
            echo "    /sys/fs/bpf/$m" >&2
        done
        exit_code=2
    else
        echo "    Clean: No eBPF rootkit traces detected."
    fi

    return $exit_code
}

check_systemd_persistence() {
    local exit_code=0
    echo " [3.2] Systemd persistence check"
    echo "  Checking for suspicious systemd services..."

    local dirs=(
        "/etc/systemd/system"
        "/usr/lib/systemd/system"
        "$HOME/.config/systemd/user"
    )

    local found=()
    for dir in "${dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r svc; do
            local content
            content=$(cat "$svc" 2>/dev/null || true)
            if echo "$content" | grep -q 'Restart=always' && \
               echo "$content" | grep -q 'RestartSec=30\|RestartSec=10' && \
               echo "$content" | grep -qiE 'exec.*/var/lib/|exec.*/dev/shm|exec.*/tmp/'; then
                found+=("$svc")
            fi
        done < <(find "$dir" -name '*.service' -type f 2>/dev/null)
    done

    if [[ ${#found[@]} -gt 0 ]]; then
        warn "Suspicious systemd services found:"
        for svc in "${found[@]}"; do
            echo "    $svc" >&2
        done
        exit_code=2
    else
        echo "    Clean: No suspicious systemd services detected."
    fi

    return $exit_code
}

check_suid_binaries() {
    local exit_code=0
    echo " [3.3] SUID binary check"
    echo "  Checking for unusual SUID binaries..."

    local tmpfile
    tmpfile=$(mktemp)

    find /usr/bin /usr/sbin /bin /sbin -type f -perm -4000 2>/dev/null | sort > "$tmpfile"

    local suspicious=()
    while IFS= read -r binary; do
        local pkg
        pkg=$(pacman -Qo "$binary" 2>/dev/null | awk '{print $NF}' | head -1 || true)
        if [[ -z "$pkg" ]]; then
            suspicious+=("$binary (not owned by any package)")
        fi
    done < "$tmpfile"

    if [[ ${#suspicious[@]} -gt 0 ]]; then
        warn "Suspicious SUID binaries found:"
        for b in "${suspicious[@]}"; do
            echo "    $b" >&2
        done
        exit_code=1
    else
        echo "    Clean: No suspicious SUID binaries."
    fi

    rm -f "$tmpfile"
    return $exit_code
}

check_npm_bun_cache() {
    local exit_code=0
    echo " [3.4] npm/bun cache check"
    echo "  Checking for malicious packages in npm/bun caches..."

    local found_npm=()
    for malicious_pkg in "${MALICIOUS_NPM_PACKAGES[@]}"; do
        if check_cmd npm >/dev/null 2>&1; then
            local npm_cache
            npm_cache=$(npm config get cache 2>/dev/null || echo "$HOME/.npm")
            if [[ -d "$npm_cache" ]]; then
                local matches
                matches=$(find "$npm_cache" -maxdepth 5 -name "*${malicious_pkg}*" -type d 2>/dev/null | head -5 || true)
                if [[ -n "$matches" ]]; then
                    while IFS= read -r match; do
                        found_npm+=("$match")
                    done <<< "$matches"
                fi
            fi

            local global_mod
            global_mod=$(npm root -g 2>/dev/null || echo "")
            if [[ -n "$global_mod" && -d "$global_mod/${malicious_pkg}" ]]; then
                found_npm+=("$global_mod/${malicious_pkg} (global node_modules)")
            fi
        fi
    done

    if [[ ${#found_npm[@]} -gt 0 ]]; then
        warn "Malicious packages found in npm cache:"
        for m in "${found_npm[@]}"; do
            echo "    $m" >&2
        done
        exit_code=2
    else
        echo "    Clean: No malicious packages in npm cache."
    fi

    local found_bun=()
    for malicious_pkg in "${MALICIOUS_NPM_PACKAGES[@]}"; do
        if check_cmd bun >/dev/null 2>&1; then
            local bun_cache
            bun_cache=$(bun pm cache 2>/dev/null || echo "$HOME/.bun/install/cache")
            if [[ -d "$bun_cache" ]]; then
                local matches
                matches=$(find "$bun_cache" -maxdepth 5 -name "*${malicious_pkg}*" -type d 2>/dev/null | head -5 || true)
                if [[ -n "$matches" ]]; then
                    while IFS= read -r match; do
                        found_bun+=("$match")
                    done <<< "$matches"
                fi
            fi
        fi
    done

    if [[ ${#found_bun[@]} -gt 0 ]]; then
        warn "Malicious packages found in bun cache:"
        for m in "${found_bun[@]}"; do
            echo "    $m" >&2
        done
        exit_code=2
    else
        echo "    Clean: No malicious packages in bun cache."
    fi

    return $exit_code
}

check_suspicious_connections() {
    local exit_code=0
    echo " [3.5] Suspicious network connection check"
    echo "  Checking for connections to known malicious hosts..."

    if ! check_cmd ss >/dev/null 2>&1; then
        echo "    ss not found; skipping."
        return 0
    fi

    # ENHANCEMENT: Added '-r' flag to 'ss' to try resolving domains, 
    # matching signatures like paste.sh or temp.sh more reliably.
    local c2_indicators=("temp.sh" ".onion" "paste.sh")
    local established
    established=$(ss -tunpra 2>/dev/null || true)

    for indicator in "${c2_indicators[@]}"; do
        if echo "$established" | grep -qi "$indicator" 2>/dev/null; then
            warn "Connection to suspicious host/process detected: $indicator"
            echo "$established" | grep -i "$indicator" >&2 || true
            exit_code=2
        fi
    done

    if [[ $exit_code -eq 0 ]]; then
        echo "    Clean: No active connections to known malicious hosts."
    fi

    return $exit_code
}

# ---------------------------------------------------------------------------
# Phase 5: AUR PKGBUILD static analysis (deep scan)
# ---------------------------------------------------------------------------

check_aur_pkgbuilds() {
    local exit_code=0
    print_separator
    echo " [4] AUR PKGBUILD static analysis (suspicious patterns)"
    print_separator

    if ! check_cmd pacman; then
        return 1
    fi

    if ! pacman -Qqm >/dev/null 2>&1; then
        info "No AUR packages installed."
        return 0
    fi

    info "Checking installed AUR packages for suspicious PKGBUILD patterns..."
    info "Note: This checks pacman's stored metadata, not live PKGBUILDs."

    local found_any=false
    local pkg_count=0
    while IFS= read -r pkg; do
        pkg_count=$((pkg_count + 1))
        local scriptlet="/var/lib/pacman/local/$pkg-*/install"
        for f in $scriptlet; do
            [[ -f "$f" ]] || continue
            local content
            content=$(cat "$f" 2>/dev/null || true)
            for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
                if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
                    warn "Suspicious pattern in $pkg: '$pattern'"
                    found_any=true
                fi
            done
        done

        # Check for known attacker accounts in the package metadata
        local pkg_info
        pkg_info=$(pacman -Qi "$pkg" 2>/dev/null || true)
        for account in "${ATTACKER_ACCOUNTS[@]}"; do
            if echo "$pkg_info" | grep -qi "$account" 2>/dev/null; then
                warn "Package $pkg references known attacker account: $account"
                found_any=true
            fi
        done
    done < <(pacman -Qqm 2>/dev/null)

    if ! $found_any; then
        info "No suspicious patterns found in $pkg_count AUR package metadata."
    else
        exit_code=2
    fi

    return $exit_code
}

# ---------------------------------------------------------------------------
# Phase 6: System anomaly scan
# ---------------------------------------------------------------------------

check_system_anomalies() {
    local exit_code=0
    print_separator
    echo " [5] System anomaly scan"
    print_separator

    echo "  Checking crontabs..."
    local cron_found=false
    for user in root "$(whoami)"; do
        local crontab
        if crontab -u "$user" -l 2>/dev/null | grep -qiE 'curl|wget|bash|/tmp/|/dev/shm' 2>/dev/null; then
            warn "Suspicious cron entry for user $user:"
            crontab -u "$user" -l 2>/dev/null | grep -iE 'curl|wget|bash|/tmp/|/dev/shm' >&2 || true
            cron_found=true
            exit_code=2
        fi
    done
    if ! $cron_found; then
        echo "    Clean: No suspicious cron jobs."
    fi

    echo "  Checking /tmp and /dev/shm for suspicious executables..."
    local tmp_found=false
    for dir in /tmp /dev/shm; do
        if [[ -d "$dir" ]]; then
            local suspicious
            suspicious=$(find "$dir" -maxdepth 2 -type f \( -executable -o -name '*.elf' -o -name 'deps' \) 2>/dev/null | head -20 || true)
            if [[ -n "$suspicious" ]]; then
                # False positive protection: Log as alert, but don't hard fail unless explicitly dangerous
                warn "Executables found in temporary directory $dir:"
                echo "$suspicious" >&2
                tmp_found=true
                exit_code=1
            fi
        fi
    done
    if ! $tmp_found; then
        echo "    Clean: No suspicious files in /tmp or /dev/shm."
    fi

    echo "  Checking for known malware binaries..."
    local malware_binaries=("deps" "js-digest" "atomic-lockfile")
    local bin_found=false
    for bin in "${malware_binaries[@]}"; do
        local location
        location=$(find /usr/bin /usr/local/bin /opt ~/.local/bin -name "$bin" -type f 2>/dev/null | head -3 || true)
        if [[ -n "$location" ]]; then
            warn "Known malware binary found: $bin at: $location"
            bin_found=true
            exit_code=2
        fi
    done
    if ! $bin_found; then
        echo "    Clean: No known malware binaries found."
    fi

    echo "  Checking for recently modified critical files..."
    local recent=''
    recent=$(find /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config \
        -newer /proc/version -mmin -1440 2>/dev/null || true)
    if [[ -n "$recent" ]]; then
        warn "Critical files modified in the last 24 hours:"
        echo "$recent" >&2
        exit_code=1
    else
        echo "    Clean: No recently modified critical files."
    fi

    return $exit_code
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --no-remote       Use embedded malicious package list only (no network)
  --integrity       Check package file integrity (pacman -Qkk)
  --deep            Deep scan (AUR PKGBUILD analysis, npm/bun cache)
  --full            Enable all checks (integrity + deep + system anomalies)
  --verbose, -v     Verbose output
  --help, -h        Show this help
EOF
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --no-remote)    USE_REMOTE=false ;;
        --integrity)    CHECK_INTEGRITY=true ;;
        --deep)         DEEP_SCAN=true ;;
        --full)         FULL_SCAN=true ;;
        --verbose|-v)   VERBOSE=true ;;
        --help|-h)      HELP=true ;;
        *)              echo "Unknown option: $arg"; usage ;;
    esac
done

$HELP && usage

if $FULL_SCAN; then
    CHECK_INTEGRITY=true
    DEEP_SCAN=true
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local exit_code=0
    local tmp_dir
    tmp_dir=$(mktemp -d)
    TEMP_DIR="$tmp_dir"
    LIST_FILE="$tmp_dir/compromised_pkgs.txt"
    local overall_infected=false
    local overall_warnings=false

    trap cleanup EXIT INT TERM

    print_banner

    if ! check_cmd pacman; then
        error "pacman not found. This script is for Arch Linux only."
        exit 1
    fi

    echo "[*] Fetching known compromised package list..."
    fetch_package_lists "$LIST_FILE"
    echo

    if check_installed_against_list "$LIST_FILE"; then
        :
    else
        local ret=$?
        if [[ $ret -eq 2 ]]; then
            overall_infected=true
            [[ $ret -gt $exit_code ]] && exit_code=$ret
        fi
    fi
    echo

    if $CHECK_INTEGRITY; then
        if check_integrity; then
            :
        else
            local ret=$?
            [[ $ret -gt $exit_code ]] && exit_code=$ret
            [[ $ret -eq 2 ]] && overall_infected=true
            [[ $ret -eq 1 ]] && overall_warnings=true
        fi
        echo
    fi

    if $DEEP_SCAN || $FULL_SCAN; then
        print_separator
        echo " [3] Malware indicator scan"
        print_separator

        if check_ebpf_rootkit; then :; else
            local ret=$?
            [[ $ret -gt $exit_code ]] && exit_code=$ret
            [[ $ret -eq 2 ]] && overall_infected=true
        fi

        if check_systemd_persistence; then :; else
            local ret=$?
            [[ $ret -gt $exit_code ]] && exit_code=$ret
            [[ $ret -eq 2 ]] && overall_infected=true
        fi

        if check_suid_binaries; then :; else
            local ret=$?
            [[ $ret -gt $exit_code ]] && exit_code=$ret
            [[ $ret -eq 1 ]] && overall_warnings=true
        fi

        if check_npm_bun_cache; then :; else
            local ret=$?
            [[ $ret -gt $exit_code ]] && exit_code=$ret
            [[ $ret -eq 2 ]] && overall_infected=true
        fi

        if check_suspicious_connections; then :; else
            local ret=$?
            [[ $ret -gt $exit_code ]] && exit_code=$ret
            [[ $ret -eq 2 ]] && overall_infected=true
        fi

        echo
    fi

    if $DEEP_SCAN || $FULL_SCAN; then
        if check_aur_pkgbuilds; then :; else
            local ret=$?
            [[ $ret -gt $exit_code ]] && exit_code=$ret
            [[ $ret -eq 2 ]] && overall_infected=true
        fi
        echo
    fi

    if $FULL_SCAN; then
        if check_system_anomalies; then :; else
            local ret=$?
            [[ $ret -gt $exit_code ]] && exit_code=$ret
            [[ $ret -eq 2 ]] && overall_infected=true
            [[ $ret -eq 1 ]] && overall_warnings=true
        fi
        echo
    fi

    echo "============================================================"
    echo "  SCAN COMPLETE"
    echo "============================================================"
    if $overall_infected; then
        echo "  RESULT: INFECTED - Indicators of compromise found."
        echo "  Action: Investigate the findings above immediately."
        exit_code=2
    elif $overall_warnings; then
        echo "  RESULT: WARNINGS - Review the non-critical findings above."
        exit_code=1
    else
        echo "  RESULT: CLEAN - No indicators of compromise detected."
        exit_code=0
    fi
    echo "============================================================"

    cleanup
    exit "$exit_code"
}

main "$@"