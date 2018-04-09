###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for squirrelmail CESA-2013:0126 centos5 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "SquirrelMail is a standards-based webmail package written in PHP.

  The SquirrelMail security update RHSA-2012:0103 did not, unlike the erratum
  text stated, correct the CVE-2010-2813 issue, a flaw in the way
  SquirrelMail handled failed log in attempts. A user preference file was
  created when attempting to log in with a password containing an 8-bit
  character, even if the username was not valid. A remote attacker could use
  this flaw to eventually consume all hard disk space on the target
  SquirrelMail server. (CVE-2012-2124)
  
  This update also fixes the following bugs:
  
  * Prior to this update, SquirrelMail could not decode multi-line subjects
  properly. Consequently, the decode header internationalization option did
  not properly handle new lines or tabs at the beginning of the lines. This
  bug has been fixed and SquirrelMail now works correctly in the described
  scenario. (BZ#241861)
  
  * Due to a bug, attachments written in HTML code on the Windows operating
  system were not displayed properly when accessed with SquirrelMail; the
  &quot;!=null&quot; string was trimmed to &quot;!ull&quot;. This bug has been fixed and the
  attachments are now displayed correctly in such a case. (BZ#359791)
  
  * Previously, e-mail messages with a Unique Identifier (UID) larger than
  2^31 bytes were unreadable when using the squirrelmail package. With this
  patch the squirrelmail package is able to read all messages regardless of
  the UIDs size. (BZ#450780)
  
  * Due to a bug, a PHP script did not assign the proper character set to
  requested variables. Consequently, SquirrelMail could not display any
  e-mails. The underlying source code has been modified and now the
  squirrelmail package assigns the correct character set. (BZ#475188)
  
  * Due to the incorrect internationalization option located at the i18n.php
  file, the squirrelmail package could not use the GB 2312 character set. The
  i18n.php file has been fixed and the GB 2312 character set works correctly
  in the described scenario. (BZ#508686)
  
  * Previously, the preg_split() function contained a misspelled constant,
  PREG_SPLIT_NI_EMPTY, which could cause SquirrelMail to produce error
  messages. The name of the constant has been corrected to
  PREG_SPLIT_NO_EMPTY, and SquirrelMail no longer produces error messages in
  this scenario. (BZ#528758)
  
  * Due to Security-Enhanced Linux (SELinux) settings, sending e-mails from
  the SquirrelMail web interface was blocked. This update adds a note to the
  SquirrelMail documentation that describes how to set the SELinux options to
  allow sending e-mails from  ... 

  Description truncated, for more information please check the Reference URL";


tag_affected = "squirrelmail on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-January/019177.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881572");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:41:41 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2012-2124", "CVE-2010-2813");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "CESA", value: "2013:0126");
  script_name("CentOS Update for squirrelmail CESA-2013:0126 centos5 ");

  script_tag(name:"summary", value:"Check for the Version of squirrelmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~21.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
