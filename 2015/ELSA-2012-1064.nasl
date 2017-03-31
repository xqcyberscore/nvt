# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1064.nasl 4513 2016-11-15 09:37:48Z cfi $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123870");
script_version("$Revision: 4513 $");
script_tag(name:"creation_date", value:"2015-10-06 14:09:39 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2016-11-15 10:37:48 +0100 (Tue, 15 Nov 2016) $");
script_name("Oracle Linux Local Check: ELSA-2012-1064");
script_tag(name: "insight", value: "ELSA-2012-1064 -  kernel security and bug fix update - [2.6.32-279.1.1.el6]- [kernel] Prevent keyctl new_session from causing a panic (David Howells) [833433 827424] {CVE-2012-2745}- [net] ipv6/netfilter: fix null pointer dereference in nf_ct_frag6_reasm() (Petr Matousek) [833410 833412] {CVE-2012-2744}- [fs] nfs: Map minor mismatch error to protocol not support error (Steve Dickson) [832365 796352]- [fs] ext4: Fix overflow caused by missing cast in ext4_fallocate() (Lukas Czerner) [833034 830209]- [ata] libata: Add 2GB ATA Flash Disk/ADMA428M to DMA blacklist (Prarit Bhargava) [832363 812904]- [netdrv] r8169: fix typo in firmware filenames (Ivan Vecera) [832359 829211]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1064");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1064.html");
script_cve_id("CVE-2012-2744","CVE-2012-2745");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_summary("Oracle Linux Local Security Checks ELSA-2012-1064");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.1.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.1.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.1.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.1.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.1.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.1.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.1.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.1.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.1.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

