# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0124.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.131274");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-03-31 08:04:59 +0300 (Thu, 31 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0124");
script_tag(name: "insight", value: "Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 allow remote attackers to bypass the Same Origin Policy via data: and view-source: URIs. (CVE-2015-7214) The WebExtension APIs in Mozilla Firefox before 43.0 allow remote attackers to gain privileges, and possibly obtain sensitive information or conduct cross-site scripting (XSS) attacks, via a crafted web site. (CVE-2015-7223) Integer underflow in the Metadata::setData function in MetaData.cpp in libstagefright in Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 allows remote attackers to execute arbitrary code or cause a denial of service (incorrect memory allocation and application crash) via an MP4 video file with crafted covr metadata that triggers a buffer overflow. (CVE-2015-7222) Integer overflow in the MPEG4Extractor::readMetaData function in MPEG4Extractor.cpp in libstagefright in Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 on 64-bit platforms allows remote attackers to execute arbitrary code via a crafted MP4 video file that triggers a buffer overflow. (CVE-2015-7213) Integer underflow in the RTPReceiverVideo::ParseRtpPacket function in Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 might allow remote attackers to obtain sensitive information, cause a denial of service, or possibly have unspecified other impact by triggering a crafted WebRTC RTP packet. (CVE-2015-7205) Buffer overflow in the DirectWriteFontInfo::LoadFontFamilyData function in gfx/thebes/gfxDWriteFontList.cpp in Mozilla Firefox before 43.0 might allow remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted font-family name. (CVE-2015-7203) Buffer overflow in the XDRBuffer::grow function in js/src/vm/Xdr.cpp in Mozilla Firefox before 43.0 might allow remote attackers to cause a denial of service or possibly have unspecified other impact via crafted JavaScript code. (CVE-2015-7220) Buffer overflow in the nsDeque::GrowCapacity function in xpcom/glue/nsDeque.cpp in Mozilla Firefox before 43.0 might allow remote attackers to cause a denial of service or possibly have unspecified other impact by triggering a deque size change. (CVE-2015-7221) The gdk-pixbuf configuration in Mozilla Firefox before 43.0 on Linux GNOME platforms incorrectly enables the JasPer decoder, which allows remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted JPEG 2000 image. (CVE-2015-7216) The gdk-pixbuf configuration in Mozilla Firefox before 43.0 on Linux GNOME platforms incorrectly enables the TGA decoder, which allows remote attackers to cause a denial of service (heap-based buffer overflow) via a crafted Truevision TGA image. (CVE-2015-7217) The HTTP/2 implementation in Mozilla Firefox before 43.0 allows remote attackers to cause a denial of service (integer underflow, assertion failure, and application exit) via a single-byte header frame that triggers incorrect memory allocation. (CVE-2015-7218) The HTTP/2 implementation in Mozilla Firefox before 43.0 allows remote attackers to cause a denial of service (integer underflow, assertion failure, and application exit) via a malformed PushPromise frame that triggers decompressed-buffer length miscalculation and incorrect memory allocation. (CVE-2015-7219) Mozilla Firefox before 43.0 mishandles the # (number sign) character in a data: URI, which allows remote attackers to spoof web sites via unspecified vectors. (CVE-2015-7211) The importScripts function in the Web Workers API implementation in Mozilla Firefox before 43.0 allows remote attackers to bypass the Same Origin Policy by triggering use of the no-cors mode in the fetch API to attempt resource access that throws an exception, leading to information disclosure after a rethrow. (CVE-2015-7215) Integer overflow in the mozilla::layers::BufferTextureClient::AllocateForSurface function in Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 allows remote attackers to execute arbitrary code by triggering a graphics operation that requires a large texture allocation. (CVE-2015-7212) Use-after-free vulnerability in Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 allows remote attackers to execute arbitrary code by triggering attempted use of a data channel that has been closed by a WebRTC function. (CVE-2015-7210) Mozilla Firefox before 43.0 stores cookies containing vertical tab characters, which allows remote attackers to obtain sensitive information by reading HTTP Cookie headers. (CVE-2015-7208) Mozilla Firefox before 43.0 does not properly restrict the availability of IFRAME Resource Timing API times, which allows remote attackers to bypass the Same Origin Policy and obtain sensitive information via crafted JavaScript code that leverages history.back and performance.getEntries calls, a related issue to CVE-2015-1300. (CVE-2015-7207) Mozilla Firefox before 43.0 does not properly store the properties of unboxed objects, which allows remote attackers to execute arbitrary code via crafted JavaScript variable assignments. (CVE-2015-7204) Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-7201) Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 43.0 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-7202)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0124.html");
script_cve_id("CVE-2015-7201","CVE-2015-7202","CVE-2015-7203","CVE-2015-7204","CVE-2015-7205","CVE-2015-7207","CVE-2015-7208","CVE-2015-7210","CVE-2015-7211","CVE-2015-7212","CVE-2015-7213","CVE-2015-7214","CVE-2015-7215","CVE-2015-7216","CVE-2015-7217","CVE-2015-7218","CVE-2015-7219","CVE-2015-7220","CVE-2015-7221","CVE-2015-7222","CVE-2015-7223");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0124");
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
if ((res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.40~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
