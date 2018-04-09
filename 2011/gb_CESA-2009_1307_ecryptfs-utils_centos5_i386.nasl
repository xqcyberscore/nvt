###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ecryptfs-utils CESA-2009:1307 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "eCryptfs is a stacked, cryptographic file system. It is transparent to the
  underlying file system and provides per-file granularity.

  eCryptfs is released as a Technology Preview for Red Hat Enterprise Linux
  5.4. These updated ecryptfs-utils packages have been upgraded to upstream
  version 75, which provides a number of bug fixes and enhancements over the
  previous version. In addition, these packages provide a graphical program
  to help configure and use eCryptfs. To start this program, run the command:
  
  	ecryptfs-mount-helper-gui
  
  Important: the syntax of certain eCryptfs mount options has changed. Users
  who were previously using the initial Technology Preview release of
  ecryptfs-utils are advised to refer to the ecryptfs(7) man page, and to
  update any affected mount scripts and /etc/fstab entries for eCryptfs file
  systems.
  
  A disclosure flaw was found in the way the &quot;ecryptfs-setup-private&quot; script
  passed passphrases to the &quot;ecryptfs-wrap-passphrase&quot; and
  &quot;ecryptfs-add-passphrase&quot; commands as command line arguments. A local user
  could obtain the passphrases of other users who were running the script
  from the process listing. (CVE-2008-5188)
  
  These updated packages provide various enhancements, including a mount
  helper and supporting libraries to perform key management and mounting
  functions.
  
  Notable enhancements include:
  
  * a new package, ecryptfs-utils-gui, has been added to this update. This
  package depends on the pygtk2 and pygtk2-libglade packages and provides the
  eCryptfs Mount Helper GUI program. To install the GUI, first install
  ecryptfs-utils and then issue the following command:
  
  	yum install ecryptfs-utils-gui
  
  (BZ#500997)
  
  * the &quot;ecryptfs-rewrite-file&quot; utility is now more intelligent when dealing
  with non-existent files and with filtering special files such as the &quot;.&quot;
  directory. In addition, the progress output from &quot;ecryptfs-rewrite-file&quot;
  has been improved and is now more explicit about the success status of each
  target. (BZ#500813)
  
  * descriptions of the &quot;verbose&quot; flag and the &quot;verbosity=[x]&quot; option, where
  [x] is either 0 or 1, were missing from a number of eCryptfs manual pages,
  and have been added. Refer to the eCryptfs man pages for important
  information regarding using the verbose and/or verbosity options.
  (BZ#470444)
  
  These updated packages also fix the following bugs:
  
  * mounting a directory using the eCryptfs mount helper with an RSA key that
  was too small did not allow the eCryptfs mou ... 

  Description truncated, for more information please check the Reference URL";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "ecryptfs-utils on CentOS 5";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-September/016145.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880867");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2009:1307");
  script_cve_id("CVE-2008-5188");
  script_name("CentOS Update for ecryptfs-utils CESA-2009:1307 centos5 i386");

  script_tag(name:"summary", value:"Check for the Version of ecryptfs-utils");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"ecryptfs-utils", rpm:"ecryptfs-utils~75~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ecryptfs-utils-devel", rpm:"ecryptfs-utils-devel~75~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ecryptfs-utils-gui", rpm:"ecryptfs-utils-gui~75~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
