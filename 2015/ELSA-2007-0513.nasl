# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2007-0513.nasl 6600 2017-07-07 09:58:31Z teissa $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.122659");
script_version("$Revision: 6600 $");
script_tag(name:"creation_date", value:"2015-10-08 14:50:27 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:58:31 +0200 (Fri, 07 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2007-0513");
script_tag(name: "insight", value: "ELSA-2007-0513 -  Moderate: gimp security update - [1.2.3-20.9.el3] - validate bytesperline header field when loading PCX files (#247570) [1.2.3-20.8.el3] - reduce GIMP_MAX_IMAGE_SIZE to 2^18 to detect bogus image widths/heights (#247570) [1.2.3-20.7.el3] - replace gimp_error() by gimp_message()/gimp_quit() in a few plugins so they don't crash but gracefully exit when encountering error conditions - fix endianness issues in the PSP plugin to avoid it doing (seemingly) endless loops when loading images - fix endianness issues in the PCX plugin which cause it to not detect corrupt images [1.2.3-20.6.el3] - add ChangeLog entry to psd-invalid-dimensions patch (#247570) - validate size values read from files before using them to allocate memory in various file plugins (#247570, patch by Mukund Sivaraman and Rapha??l Quinet, adapted) - detect invalid image data when reading files in several plugins (#247570, patch by Sven Neumann and Rapha??l Quinet, adapted) - validate size values read from files before using them to allocate memory in the PSD and sunras plugins (#247570, patch by Mukund Sivaraman and Sven Neumann, partly adapted) - add safeguard to avoid crashes while loading corrupt PSD images (#247570, patch by Rapha??l Quinet, adapted) - convert spec file to UTF-8 [1.2.3-20.5.el3] - use adapted upstream PSD fix by Sven Neumann (#244406) [1.2.3-20.4.el3] - refuse to open PSD files with insanely large dimensions (#244406)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2007-0513");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2007-0513.html");
script_cve_id("CVE-2006-4519","CVE-2007-2949","CVE-2007-3741");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.2.13~2.0.7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.2.13~2.0.7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~2.2.13~2.0.7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

