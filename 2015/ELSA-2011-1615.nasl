# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1615.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122027");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:53 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1615");
script_tag(name: "insight", value: "ELSA-2011-1615 -  virt-v2v security and bug fix update - [0.8.3-5]- Fix regression when converting Win7 32 bit to RHEV (RHBZ#738236)[0.8.3-4][element][0.8.3-3]- Add missing dependency on new Sys::Virt[0.8.3-2]- Fix for CVE-2011-1773- Document limitations wrt Windows Recovery Console[0.8.3-1]- Include missing virt-v2v.db- Rebase to upstream release 0.8.3[0.8.2-2]- Split configuration into /etc/virt-v2v.conf and /var/lib/virt-v2v/virt-v2v.db- Improve usability as non-root user (RHBZ#671094)- Update man pages to use -os as appropriate (RHBZ#694370)- Warn if user specifies both -n and -b (RHBZ#700759)- Fix cleanup when multiboot OS is detected (RHBZ#702007)- Ensure the cirrus driver is installed if required (RHBZ#708961)- Remove unnecessary dep on perl(IO::Handle)- Fix conversion of xen guests using aio storage backend.- Suppress warning for chainloader grub entries.- Only configure a single scsi_hostadapter for converted VMware guests.[0.8.2-1]- Rebase to upstream release 0.8.2[0.7.1-4]- Fix detection of Windows XP Pro x64 (RHBZ#679017)- Fix error message when converting Red Hat Desktop (RHBZ#678950)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1615");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1615.html");
script_cve_id("CVE-2011-1773");
script_tag(name:"cvss_base", value:"4.4");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"virt-v2v", rpm:"virt-v2v~0.8.3~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

