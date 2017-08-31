# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1507.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123071");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:58:59 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1507");
script_tag(name: "insight", value: "ELSA-2015-1507 -  qemu-kvm security and bug fix update - [1.5.3-86.el7_1.5]- kvm-i8254-fix-out-of-bounds-memory-access-in-pit_ioport_.patch [bz#1243726]- Resolves: bz#1243726 (CVE-2015-3214 qemu-kvm: qemu: i8254: out-of-bounds memory access in pit_ioport_read function [rhel-7.1.z])[1.5.3-86.el7_1.4]- kvm-ide-Check-array-bounds-before-writing-to-io_buffer-C.patch [bz#1243689]- kvm-ide-atapi-Fix-START-STOP-UNIT-command-completion.patch [bz#1243689]- kvm-ide-Clear-DRQ-after-handling-all-expected-accesses.patch [bz#1243689]- Resolves: bz#1243689 (EMBARGOED CVE-2015-5154 qemu-kvm: qemu: ide: atapi: heap overflow during I/O buffer memory access [rhel-7.1.z])[1.5.3-86.el7_1.3]- kvm-atomics-add-explicit-compiler-fence-in-__atomic-memo.patch [bz#1233643]- Resolves: bz#1233643 ([abrt] qemu-kvm: bdrv_error_action(): qemu-kvm killed by SIGABRT)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1507");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1507.html");
script_cve_id("CVE-2015-3214","CVE-2015-5154");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~86.el7_1.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~86.el7_1.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~86.el7_1.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~86.el7_1.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~86.el7_1.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~86.el7_1.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~86.el7_1.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

