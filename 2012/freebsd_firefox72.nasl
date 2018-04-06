#
#VID d23119df-335d-11e2-b64c-c8600054b392
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID d23119df-335d-11e2-b64c-c8600054b392
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "The following packages are affected:
   firefox
   linux-firefox
   linux-seamonkey
   linux-thunderbird
   seamonkey
   thunderbird
   libxul

CVE-2012-4201
The evalInSandbox implementation in Mozilla Firefox before 17.0,
Firefox ESR 10.x before 10.0.11, Thunderbird before 17.0, Thunderbird
ESR 10.x before 10.0.11, and SeaMonkey before 2.14 uses an incorrect
context during the handling of JavaScript code that sets the
location.href property, which allows remote attackers to conduct
cross-site scripting (XSS) attacks or read arbitrary files by
leveraging a sandboxed add-on.
CVE-2012-4202
Heap-based buffer overflow in the image::RasterImage::DrawFrameTo
function in Mozilla Firefox before 17.0, Firefox ESR 10.x before
10.0.11, Thunderbird before 17.0, Thunderbird ESR 10.x before 10.0.11,
and SeaMonkey before 2.14 allows remote attackers to execute arbitrary
code via a crafted GIF image.
CVE-2012-4203
The New Tab page in Mozilla Firefox before 17.0 uses a privileged
context for execution of JavaScript code by bookmarklets, which allows
user-assisted remote attackers to run arbitrary programs by leveraging
a javascript: URL in a bookmark.
CVE-2012-4204
The str_unescape function in the JavaScript engine in Mozilla Firefox
before 17.0, Thunderbird before 17.0, and SeaMonkey before 2.14 allows
remote attackers to execute arbitrary code or cause a denial of
service (memory corruption and application crash) via unspecified
vectors.
CVE-2012-4205
Mozilla Firefox before 17.0, Thunderbird before 17.0, and SeaMonkey
before 2.14 assign the system principal, rather than the sandbox
principal, to XMLHttpRequest objects created in sandboxes, which
allows remote attackers to conduct cross-site request forgery (CSRF)
attacks or obtain sensitive information by leveraging a sandboxed
add-on.
CVE-2012-4206
Untrusted search path vulnerability in the installer in Mozilla
Firefox before 17.0 and Firefox ESR 10.x before 10.0.11 on Windows
allows local users to gain privileges via a Trojan horse DLL in the
default downloads directory.
CVE-2012-4207
The HZ-GB-2312 character-set implementation in Mozilla Firefox before
17.0, Firefox ESR 10.x before 10.0.11, Thunderbird before 17.0,
Thunderbird ESR 10.x before 10.0.11, and SeaMonkey before 2.14 does
not properly handle a ~ (tilde) character in proximity to a chunk
delimiter, which allows remote attackers to conduct cross-site
scripting (XSS) attacks via a crafted document.
CVE-2012-4208
The XrayWrapper implementation in Mozilla Firefox before 17.0,
Thunderbird before 17.0, and SeaMonkey before 2.14 does not consider
the compartment during property filtering, which allows remote
attackers to bypass intended chrome-only restrictions on reading DOM
object properties via a crafted web site.
CVE-2012-4209
Mozilla Firefox before 17.0, Firefox ESR 10.x before 10.0.11,
Thunderbird before 17.0, Thunderbird ESR 10.x before 10.0.11, and
SeaMonkey before 2.14 do not prevent use of a 'top' frame
name-attribute value to access the location property, which makes it
easier for remote attackers to conduct cross-site scripting (XSS)
attacks via vectors involving a binary plugin.
CVE-2012-4210
The Style Inspector in Mozilla Firefox before 17.0 and Firefox ESR
10.x before 10.0.11 does not properly restrict the context of HTML
markup and Cascading Style Sheets (CSS) token sequences, which allows
user-assisted remote attackers to execute arbitrary JavaScript code
with chrome privileges via a crafted stylesheet.
CVE-2012-4212
Use-after-free vulnerability in the XPCWrappedNative::Mark function in
Mozilla Firefox before 17.0, Thunderbird before 17.0, and SeaMonkey
before 2.14 allows remote attackers to execute arbitrary code or cause
a denial of service (heap memory corruption) via unspecified vectors.
CVE-2012-4213
Use-after-free vulnerability in the nsEditor::FindNextLeafNode
function in Mozilla Firefox before 17.0, Thunderbird before 17.0, and
SeaMonkey before 2.14 allows remote attackers to execute arbitrary
code or cause a denial of service (heap memory corruption) via
unspecified vectors.
CVE-2012-4214
Use-after-free vulnerability in the nsTextEditorState::PrepareEditor
function in Mozilla Firefox before 17.0, Firefox ESR 10.x before
10.0.11, Thunderbird before 17.0, Thunderbird ESR 10.x before 10.0.11,
and SeaMonkey before 2.14 allows remote attackers to execute arbitrary
code or cause a denial of service (heap memory corruption) via
unspecified vectors, a different vulnerability than CVE-2012-5840.
CVE-2012-4215
Use-after-free vulnerability in the
nsPlaintextEditor::FireClipboardEvent function in Mozilla Firefox
before 17.0, Firefox ESR 10.x before 10.0.11, Thunderbird before 17.0,
Thunderbird ESR 10.x before 10.0.11, and SeaMonkey before 2.14 allows
remote attackers to execute arbitrary code or cause a denial of
service (heap memory corruption) via unspecified vectors.
CVE-2012-4216
Use-after-free vulnerability in the gfxFont::GetFontEntry function in
Mozilla Firefox before 17.0, Firefox ESR 10.x before 10.0.11,
Thunderbird before 17.0, Thunderbird ESR 10.x before 10.0.11, and
SeaMonkey before 2.14 allows remote attackers to execute arbitrary
code or cause a denial of service (heap memory corruption) via
unspecified vectors.
CVE-2012-4217
Use-after-free vulnerability in the
nsViewManager::ProcessPendingUpdates function in Mozilla Firefox
before 17.0, Thunderbird before 17.0, and SeaMonkey before 2.14 allows
remote attackers to execute arbitrary code or cause a denial of
service (heap memory corruption) via unspecified vectors.
CVE-2012-4218
Use-after-free vulnerability in the
BuildTextRunsScanner::BreakSink::SetBreaks function in Mozilla Firefox
before 17.0, Thunderbird before 17.0, and SeaMonkey before 2.14 allows
remote attackers to execute arbitrary code or cause a denial of
service (heap memory corruption) via unspecified vectors.
CVE-2012-5829
Heap-based buffer overflow in the nsWindow::OnExposeEvent function in
Mozilla Firefox before 17.0, Firefox ESR 10.x before 10.0.11,
Thunderbird before 17.0, Thunderbird ESR 10.x before 10.0.11, and
SeaMonkey before 2.14 allows remote attackers to execute arbitrary
code via unspecified vectors.
CVE-2012-5830
Use-after-free vulnerability in Mozilla Firefox before 17.0, Firefox
ESR 10.x before 10.0.11, Thunderbird before 17.0, Thunderbird ESR 10.x
before 10.0.11, and SeaMonkey before 2.14 on Mac OS X allows remote
attackers to execute arbitrary code via an HTML document.
CVE-2012-5833
The texImage2D implementation in the WebGL subsystem in Mozilla
Firefox before 17.0, Firefox ESR 10.x before 10.0.11, Thunderbird
before 17.0, Thunderbird ESR 10.x before 10.0.11, and SeaMonkey before
2.14 does not properly interact with Mesa drivers, which allows remote
attackers to execute arbitrary code or cause a denial of service
(memory corruption and application crash) via function calls involving
certain values of the level parameter.
CVE-2012-5835
Integer overflow in the WebGL subsystem in Mozilla Firefox before
17.0, Firefox ESR 10.x before 10.0.11, Thunderbird before 17.0,
Thunderbird ESR 10.x before 10.0.11, and SeaMonkey before 2.14 allows
remote attackers to execute arbitrary code or cause a denial of
service (invalid write operation) via crafted data.
CVE-2012-5836
Mozilla Firefox before 17.0, Thunderbird before 17.0, and SeaMonkey
before 2.14 allow remote attackers to execute arbitrary code or cause
a denial of service (application crash) via vectors involving the
setting of Cascading Style Sheets (CSS) properties in conjunction with
SVG text.
CVE-2012-5837
The Web Developer Toolbar in Mozilla Firefox before 17.0 executes
script with chrome privileges, which allows user-assisted remote
attackers to conduct cross-site scripting (XSS) attacks via a crafted
string.
CVE-2012-5838
The copyTexImage2D implementation in the WebGL subsystem in Mozilla
Firefox before 17.0, Thunderbird before 17.0, and SeaMonkey before
2.14 allows remote attackers to execute arbitrary code or cause a
denial of service (memory corruption and application crash) via large
image dimensions.
CVE-2012-5839
Heap-based buffer overflow in the
gfxShapedWord::CompressedGlyph::IsClusterStart function in Mozilla
Firefox before 17.0, Firefox ESR 10.x before 10.0.11, Thunderbird
before 17.0, Thunderbird ESR 10.x before 10.0.11, and SeaMonkey before
2.14 allows remote attackers to execute arbitrary code via unspecified
vectors.
CVE-2012-5840
Use-after-free vulnerability in the nsTextEditorState::PrepareEditor
function in Mozilla Firefox before 17.0, Firefox ESR 10.x before
10.0.11, Thunderbird before 17.0, Thunderbird ESR 10.x before 10.0.11,
and SeaMonkey before 2.14 allows remote attackers to execute arbitrary
code or cause a denial of service (heap memory corruption) via
unspecified vectors, a different vulnerability than CVE-2012-4214.
CVE-2012-5841
Mozilla Firefox before 17.0, Firefox ESR 10.x before 10.0.11,
Thunderbird before 17.0, Thunderbird ESR 10.x before 10.0.11, and
SeaMonkey before 2.14 implement cross-origin wrappers with a filtering
behavior that does not properly restrict write actions, which allows
remote attackers to conduct cross-site scripting (XSS) attacks via a
crafted web site.
CVE-2012-5842
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 17.0, Firefox ESR 10.x before 10.0.11, Thunderbird
before 17.0, Thunderbird ESR 10.x before 10.0.11, and SeaMonkey before
2.14 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via unknown vectors.
CVE-2012-5843
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 17.0, Thunderbird before 17.0, and SeaMonkey before
2.14 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via unknown vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/announce/2012/mfsa2012-90.html
http://www.mozilla.org/security/announce/2012/mfsa2012-91.html
http://www.mozilla.org/security/announce/2012/mfsa2012-92.html
http://www.mozilla.org/security/announce/2012/mfsa2012-93.html
http://www.mozilla.org/security/announce/2012/mfsa2012-94.html
http://www.mozilla.org/security/announce/2012/mfsa2012-95.html
http://www.mozilla.org/security/announce/2012/mfsa2012-96.html
http://www.mozilla.org/security/announce/2012/mfsa2012-97.html
http://www.mozilla.org/security/announce/2012/mfsa2012-98.html
http://www.mozilla.org/security/announce/2012/mfsa2012-99.html
http://www.mozilla.org/security/announce/2012/mfsa2012-100.html
http://www.mozilla.org/security/announce/2012/mfsa2012-101.html
http://www.mozilla.org/security/announce/2012/mfsa2012-102.html
http://www.mozilla.org/security/announce/2012/mfsa2012-103.html
http://www.mozilla.org/security/announce/2012/mfsa2012-104.html
http://www.mozilla.org/security/announce/2012/mfsa2012-105.html
http://www.mozilla.org/security/announce/2012/mfsa2012-106.html
http://www.mozilla.org/security/known-vulnerabilities/
http://www.vuxml.org/freebsd/d23119df-335d-11e2-b64c-c8600054b392.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72599");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4203", "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4206", "CVE-2012-4207", "CVE-2012-4208", "CVE-2012-4209", "CVE-2012-4210", "CVE-2012-4212", "CVE-2012-4213", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-4217", "CVE-2012-4218", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5836", "CVE-2012-5837", "CVE-2012-5838", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842", "CVE-2012-5843");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-11-26 12:47:32 -0500 (Mon, 26 Nov 2012)");
 script_name("FreeBSD Ports: firefox");


 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
txt = "";
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"11.0,1")>0 && revcomp(a:bver, b:"17.0,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.11,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.11,1")<0) {
    txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.14")<0) {
    txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.11")<0) {
    txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.14")<0) {
    txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"11.0")>0 && revcomp(a:bver, b:"17.0")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.11")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"10.0.11")<0) {
    txt += "Package libxul version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99);
}
