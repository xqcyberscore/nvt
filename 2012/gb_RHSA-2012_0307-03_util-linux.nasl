###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for util-linux RHSA-2012:0307-03
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The util-linux package contains a large variety of low-level system
  utilities that are necessary for a Linux system to function. Among others,
  util-linux contains the fdisk configuration tool and the login program.

  Multiple flaws were found in the way the mount and umount commands
  performed mtab (mounted file systems table) file updates. A local,
  unprivileged user allowed to mount or unmount file systems could use these
  flaws to corrupt the mtab file and create a stale lock file, preventing
  other users from mounting and unmounting file systems. (CVE-2011-1675,
  CVE-2011-1677)

  This update also fixes the following bugs:

  * When the user logged into a telnet server, the login utility did not
  update the utmp database properly if the utility was executed from the
  telnetd daemon. This was due to telnetd not creating an appropriate entry
  in a utmp file before executing login. With this update, correct entries
  are created and the database is updated properly. (BZ#646300)

  * Various options were not described on the blockdev(8) manual page. With
  this update, the blockdev(8) manual page includes all the relevant options.
  (BZ#650937)

  * Prior to this update, the build process of the util-linux package failed
  in the po directory with the following error message: &quot;@MKINSTALLDIRS@:
  No such file or directory&quot;. An upstream patch has been applied to address
  this issue, and the util-linux package now builds successfully. (BZ#677452)

  * Previously, the ipcs(1) and ipcrm(1) manual pages mentioned an invalid
  option, &quot;-b&quot;. With this update, only valid options are listed on those
  manual pages. (BZ#678407)

  * Previously, the mount(8) manual page contained incomplete information
  about the ext4 and XFS file systems. With this update, the mount(8) manual
  page contains the missing information. (BZ#699639)

  In addition, this update adds the following enhancements:

  * Previously, if DOS mode was enabled on a device, the fdisk utility could
  report error messages similar to the following:

  Partition 1 has different physical/logical beginnings (non-Linux?):
  phys=(0, 1, 1) logical=(0, 2, 7)

  This update enables users to switch off DOS compatible mode (by specifying
  the &quot;-c&quot; option), and such error messages are no longer displayed.
  (BZ#678430)

  * This update adds the &quot;fsfreeze&quot; command which halts access to a file
  system on a disk. (BZ#726572)

  All users of util-linux are advised to upgrade to this updated package,
  which contains backported patches to correct these issues and add these
  enhancements.";

tag_affected = "util-linux on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-February/msg00049.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870552");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:56:41 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-1675", "CVE-2011-1677");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2012:0307-03");
  script_name("RedHat Update for util-linux RHSA-2012:0307-03");

  script_tag(name: "summary" , value: "Check for the Version of util-linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.13~0.59.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"util-linux-debuginfo", rpm:"util-linux-debuginfo~2.13~0.59.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
