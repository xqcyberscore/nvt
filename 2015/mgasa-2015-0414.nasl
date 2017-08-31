# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0414.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131106");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-27 12:54:49 +0200 (Tue, 27 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0414");
script_tag(name: "insight", value: "Updated iceape packages fix security issues. The sqlite3 package has been updated as well since the new iceape version requires the SQLITE_ENABLE_DBSTAT_VTAB feature to be enabled in sqlite. This sqlite3 update also enables ICU support, fixing bug #16814 . Use-after-free vulnerability in the MediaStream playback feature in Mozilla Firefox before 40.0 allows remote attackers to execute arbitrary code via unspecified use of the Web Audio API. (CVE-2015-4477) Mozilla Firefox before 40.0 allows man-in-the-middle attackers to bypass a mixed-content protection mechanism via a feed: URL in a POST request. (CVE-2015-4483) The nsCSPHostSrc::permits function in dom/security/nsCSPUtils.cpp in Mozilla Firefox before 40.0 does not implement the Content Security Policy Level 2 exceptions for the blob, data, and filesystem URL schemes during wildcard source-expression matching, which might make it easier for remote attackers to conduct cross-site scripting (XSS) attacks by leveraging unexpected policy-enforcement behavior. (CVE-2015-4490) Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-4500) Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 41.0 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-4501) The lut_inverse_interp16 function in the QCMS library in Mozilla Firefox before 41.0 allows remote attackers to obtain sensitive information or cause a denial of service (buffer over-read and application crash) via crafted attributes in the ICC 4 profile of an image. (CVE-2015-4504) The SavedStacks class in the JavaScript implementation in Mozilla Firefox before 41.0, when the Debugger API is enabled, allows remote attackers to cause a denial of service (getSlotRef assertion failure and application exit) or possibly execute arbitrary code via a crafted web site. (CVE-2015-4507) Mozilla Firefox before 41.0, when reader mode is enabled, allows remote attackers to spoof the relationship between address-bar URLs and web content via a crafted web site. (CVE-2015-4508) Race condition in the WorkerPrivate::NotifyFeatures function in Mozilla Firefox before 41.0 allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free and application crash) by leveraging improper interaction between shared workers and the IndexedDB implementation. (CVE-2015-4510) Heap-based buffer overflow in the nestegg_track_codec_data function in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 allows remote attackers to execute arbitrary code via a crafted header in a WebM video. (CVE-2015-4511) Use-after-free vulnerability in the HTMLVideoElement interface in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 allows remote attackers to execute arbitrary code via crafted JavaScript code that modifies the URI table of a media element, aka ZDI-CAN-3176. (CVE-2015-4509) gfx/2d/DataSurfaceHelpers.cpp in Mozilla Firefox before 41.0 on Linux improperly attempts to use the Cairo library with 32-bit color-depth surface creation followed by 16-bit color-depth surface display, which allows remote attackers to obtain sensitive information from process memory or cause a denial of service (out-of-bounds read) by using a CANVAS element to trigger 2D rendering. (CVE-2015-4512) js/src/proxy/Proxy.cpp in Mozilla Firefox before 41.0 mishandles certain receiver arguments, which allows remote attackers to bypass intended window access restrictions via a crafted web site. (CVE-2015-4502) Mozilla Firefox before 41.0 allows remote attackers to bypass certain ECMAScript 5 (aka ES5) API protection mechanisms and modify immutable properties, and consequently execute arbitrary JavaScript code with chrome privileges, via a crafted web page that does not use ES5 APIs. (CVE-2015-4516) Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 allow user-assisted remote attackers to bypass intended access restrictions and discover a redirect's target URL via crafted JavaScript code that executes after a drag-and-drop action of an image into a TEXTBOX element. (CVE-2015-4519) Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 allow remote attackers to bypass CORS preflight protection mechanisms by leveraging (1) duplicate cache-key generation or (2) retrieval of a value from an incorrect HTTP Access-Control-* response header. (CVE-2015-4520) NetworkUtils.cpp in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 might allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via unknown vectors. (CVE-2015-4517) The ConvertDialogOptions function in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 might allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via unknown vectors. (CVE-2015-4521) The nsUnicodeToUTF8::GetMaxLength function in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 might allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via unknown vectors, related to an overflow. (CVE-2015-4522) The nsAttrAndChildArray::GrowBy function in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 might allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via unknown vectors, related to an overflow. (CVE-2015-7174) The XULContentSinkImpl::AddText function in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 might allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via unknown vectors, related to an overflow. (CVE-2015-7175) The AnimationThread function in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 uses an incorrect argument to the sscanf function, which might allow remote attackers to cause a denial of service (stack-based buffer overflow and application crash) or possibly have unspecified other impact via unknown vectors. (CVE-2015-7176) The InitTextures function in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 might allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via unknown vectors. (CVE-2015-7177)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0414.html");
script_cve_id("CVE-2015-4477","CVE-2015-4483","CVE-2015-4490","CVE-2015-4500","CVE-2015-4501","CVE-2015-4504","CVE-2015-4507","CVE-2015-4508","CVE-2015-4510","CVE-2015-4511","CVE-2015-4509","CVE-2015-4512","CVE-2015-4502","CVE-2015-4516","CVE-2015-4519","CVE-2015-4520","CVE-2015-4517","CVE-2015-4521","CVE-2015-4522","CVE-2015-7174","CVE-2015-7175","CVE-2015-7176","CVE-2015-7177");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0414");
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
if ((res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.8.10.2~1.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.38~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
