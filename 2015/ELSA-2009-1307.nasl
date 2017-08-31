# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-1307.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122447");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:45:32 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-1307");
script_tag(name: "insight", value: "ELSA-2009-1307 -  ecryptfs-utils security, bug fix, and enhancement update - [75-4]- fix EOF handling (#499367)- add icon to gui desktop file[75-3]- ask for password confirmation when creating openssl key (#500850)- removed executable permission from ecryptfs-dot-private (#500817)- ecryptfs-rewrite-file: improve of progress output (#500813)- dont error out when unwrapping and adding a key that already exists (#500810)- fix typo in ecryptfs-rewrite-file(1) (#500804)- add error message about full keyring (#501460)- gui sub-package must requires pygtk2-libglade (#500997)- require cryptsetup-luks for encrypted swap (#500824)- use blkid instead of vol_id (#500820)- dont rely on cryptdisks service (#500829)[75-2]- dont hang when used with wrong/missing stdin (#499367)- dont print error when key already removed (#499167)- refuse mounting with too small rsa key (#499175)- dont error out when adding key that already exists (#500361)- allow only working key sizes (#500352)- retutn nonzero when fnek is not supported (#500566)- add icon for Access-Your-Private-Data.desktop file (#500623)- fix information about openssl_passwd in openssl_passwd_file (#499128)- dont list mount.ecryptfs_private twice[75-1]- update to 75 and drop some patches[74-24]- add suid mount.ecryptfs_private, restrict it to ecryptfs group[74-23]- skip releases -2 - -22 to be sure its always newer nvr[74-22]- drop setuid for mount.ecryptfs_private - resolves: #482834[74-1]- update to 74- fix difference between apps. real names and names in usage messages (#475969)- describe verobse and verbosity=X in man page (#470444)- adding passphrase to keyring is fixed (#469662)- mount wont fail with wrong/empty input to yes/no questions (#466210)- try to load modules instead of failing when its missing (#460496)- fix wrong return codes (#479429)- resolves: #482834"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-1307");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-1307.html");
script_cve_id("CVE-2008-5188");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"ecryptfs-utils", rpm:"ecryptfs-utils~75~5.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ecryptfs-utils-devel", rpm:"ecryptfs-utils-devel~75~5.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ecryptfs-utils-gui", rpm:"ecryptfs-utils-gui~75~5.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

