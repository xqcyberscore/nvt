# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0342.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.130044");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:41:56 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0342");
script_tag(name: "insight", value: "Updated iceape packages fix security issues: Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 37.0, Firefox ESR 31.x before 31.6, and Thunderbird before 31.6 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-0814, CVE-2015-0815) Use-after-free vulnerability in the AppendElements function in Mozilla Firefox before 37.0, Firefox ESR 31.x before 31.6, and Thunderbird before 31.6 on Linux, when the Fluendo MP3 plugin for GStreamer is used, allows remote attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via a crafted MP3 file. (CVE-2015-0813) Mozilla Firefox before 37.0 does not require an HTTPS session for lightweight theme add-on installations, which allows man-in-the-middle attackers to bypass an intended user-confirmation requirement by deploying a crafted web site and conducting a DNS spoofing attack against a mozilla.org subdomain. (CVE-2015-0812) Mozilla Firefox before 37.0, Firefox ESR 31.x before 31.6, and Thunderbird before 31.6 do not properly restrict resource: URLs, which makes it easier for remote attackers to execute arbitrary JavaScript code with chrome privileges by leveraging the ability to bypass the Same Origin Policy, as demonstrated by the resource: URL associated with PDF.js. (CVE-2015-0816) The QCMS implementation in Mozilla Firefox before 37.0 allows remote attackers to obtain sensitive information from process heap memory or cause a denial of service (out-of-bounds read) via an image that is improperly handled during transformation. (CVE-2015-0811) The webrtc::VPMContentAnalysis::Release function in the WebRTC implementation in Mozilla Firefox before 37.0 uses incompatible approaches to the deallocation of memory for simple-type arrays, which might allow remote attackers to cause a denial of service (memory corruption) via unspecified vectors. (CVE-2015-0808) The navigator.sendBeacon implementation in Mozilla Firefox before 37.0, Firefox ESR 31.x before 31.6, and Thunderbird before 31.6 processes HTTP 30x status codes for redirects after a preflight request has occurred, which allows remote attackers to bypass intended CORS access-control checks and conduct cross-site request forgery (CSRF) attacks via a crafted web site, a similar issue to CVE-2014-8638. (CVE-2015-0807) The Off Main Thread Compositing (OMTC) implementation in Mozilla Firefox before 37.0 makes an incorrect memset call during interaction with the mozilla::layers::BufferTextureClient::AllocateForSurface function, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via vectors that trigger rendering of 2D graphics content. (CVE-2015-0805) The Off Main Thread Compositing (OMTC) implementation in Mozilla Firefox before 37.0 attempts to use memset for a memory region of negative length during interaction with the mozilla::layers::BufferTextureClient::AllocateForSurface function, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via vectors that trigger rendering of 2D graphics content. (CVE-2015-0806) The HTMLSourceElement::AfterSetAttr function in Mozilla Firefox before 37.0 does not properly constrain the original data type of a casted value during the setting of a SOURCE element's attributes, which allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via a crafted HTML document. (CVE-2015-0803) The HTMLSourceElement::BindToTree function in Mozilla Firefox before 37.0 does not properly constrain a data type after omitting namespace validation during certain tree-binding operations, which allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via a crafted HTML document containing a SOURCE element. (CVE-2015-0804) Mozilla Firefox before 37.0, Firefox ESR 31.x before 31.6, and Thunderbird before 31.6 allow remote attackers to bypass the Same Origin Policy and execute arbitrary JavaScript code with chrome privileges via vectors involving anchor navigation, a similar issue to CVE-2015-0818. (CVE-2015-0801) Mozilla Firefox before 37.0 relies on docshell type information instead of page principal information for Window.webidl access control, which might allow remote attackers to execute arbitrary JavaScript code with chrome privileges via certain content navigation that leverages the reachability of a privileged window with an unintended persistence of access to restricted internal methods. (CVE-2015-0802) The HTTP Alternative Services feature in Mozilla Firefox before 37.0.1 allows man-in-the-middle attackers to bypass an intended X.509 certificate-verification step for an SSL server by specifying that server in the uri-host field of an Alt-Svc HTTP/2 response header. (CVE-2015-0799) Race condition in the AsyncPaintWaitEvent::AsyncPaintWaitEvent function in Mozilla Firefox before 37.0.2 allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via a crafted plugin that does not properly complete initialization. (CVE-2015-2706) Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 38.0, Firefox ESR 31.x before 31.7, and Thunderbird before 31.7 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-2708) Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 38.0 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-2709) Heap-based buffer overflow in the SVGTextFrame class in Mozilla Firefox before 38.0, Firefox ESR 31.x before 31.7, and Thunderbird before 31.7 allows remote attackers to execute arbitrary code via crafted SVG graphics data in conjunction with a crafted Cascading Style Sheets (CSS) token sequence. (CVE-2015-2710) Mozilla Firefox before 38.0 does not recognize a referrer policy delivered by a referrer META element in cases of context-menu navigation and middle-click navigation, which allows remote attackers to obtain sensitive information by reading web-server Referer logs that contain private data in a URL, as demonstrated by a private path component. (CVE-2015-2711) The asm.js implementation in Mozilla Firefox before 38.0 does not properly determine heap lengths during identification of cases in which bounds checking may be safely skipped, which allows remote attackers to trigger out-of-bounds write operations and possibly execute arbitrary code, or trigger out-of-bounds read operations and possibly obtain sensitive information from process memory, via crafted JavaScript. (CVE-2015-2712) Use-after-free vulnerability in the SetBreaks function in Mozilla Firefox before 38.0, Firefox ESR 31.x before 31.7, and Thunderbird before 31.7 allows remote attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via a document containing crafted text in conjunction with a Cascading Style Sheets (CSS) token sequence containing properties related to vertical text. (CVE-2015-2713) Race condition in the nsThreadManager::RegisterCurrentThread function in Mozilla Firefox before 38.0 allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free and heap memory corruption) by leveraging improper Media Decoder Thread creation at the time of a shutdown. (CVE-2015-2715) Buffer overflow in the XML parser in Mozilla Firefox before 38.0, Firefox ESR 31.x before 31.7, and Thunderbird before 31.7 allows remote attackers to execute arbitrary code by providing a large amount of compressed XML data. (CVE-2015-2716) Integer overflow in libstagefright in Mozilla Firefox before 38.0 allows remote attackers to execute arbitrary code or cause a denial of service (heap-based buffer overflow and out-of-bounds read) via an MP4 video file containing invalid metadata. (CVE-2015-2717) The WebChannel.jsm module in Mozilla Firefox before 38.0 allows remote attackers to bypass the Same Origin Policy and obtain sensitive webchannel-response data via a crafted web site containing an IFRAME element referencing a different web site that is intended to read this data. (CVE-2015-2718) Multiple integer overflows in libstagefright in Mozilla Firefox before 38.0 allow remote attackers to execute arbitrary code via crafted sample metadata in an MPEG-4 video file. (CVE-2015-4496)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0342.html");
script_cve_id("CVE-2015-0799","CVE-2015-0801","CVE-2015-0802","CVE-2015-0803","CVE-2015-0804","CVE-2015-0805","CVE-2015-0806","CVE-2015-0807","CVE-2015-0808","CVE-2015-0811","CVE-2015-0812","CVE-2015-0813","CVE-2015-0814","CVE-2015-0815","CVE-2015-0816","CVE-2015-2706","CVE-2015-2708","CVE-2015-2709","CVE-2015-2710","CVE-2015-2711","CVE-2015-2712","CVE-2015-2713","CVE-2015-2715","CVE-2015-2716","CVE-2015-2717","CVE-2015-2718","CVE-2015-4496","CVE-2014-8638","CVE-2015-0818");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0342");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.35~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
