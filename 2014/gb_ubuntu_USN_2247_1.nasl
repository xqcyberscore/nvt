###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2247_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for nova USN-2247-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841862");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-06-23 16:37:31 +0530 (Mon, 23 Jun 2014)");
  script_cve_id("CVE-2013-1068", "CVE-2013-4463", "CVE-2013-4469", "CVE-2013-6491",
                "CVE-2013-7130", "CVE-2014-0134", "CVE-2014-0167");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_name("Ubuntu Update for nova USN-2247-1");

  tag_insight = "Darragh O'Reilly discovered that OpenStack Nova did not
properly set up its sudo configuration. If a different flaw was found in
OpenStack Nova, this vulnerability could be used to escalate privileges. This
issue only affected Ubuntu 13.10 and Ubuntu 14.04 LTS. (CVE-2013-1068)

Bernhard M. Wiedemann and Pedraig Brady discovered that OpenStack Nova did
not properly verify the virtual size of a QCOW2 images. A remote
authenticated attacker could exploit this to create a denial of service via
disk consumption. This issue did not affect Ubuntu 14.04 LTS.
(CVE-2013-4463, CVE-2013-4469)

JuanFra Rodriguez Cardoso discovered that OpenStack Nova did not enforce
SSL connections when Nova was configured to use QPid and qpid_protocol is
set to 'ssl'. If a remote attacker were able to perform a man-in-the-middle
attack, this flaw could be exploited to view sensitive information. Ubuntu
does not use QPid with Nova by default. This issue did not affect Ubuntu
14.04 LTS. (CVE-2013-6491)

Loganathan Parthipan discovered that OpenStack Nova did not properly create
expected files during KVM live block migration. A remote authenticated
attacker could exploit this to obtain root disk snapshot contents via
ephemeral storage. This issue did not affect Ubuntu 14.04 LTS.
(CVE-2013-7130)

Stanislaw Pitucha discovered that OpenStack Nova did not enforce the image
format when rescuing an instance. A remote authenticated attacker could
exploit this to read host files. In the default installation, attackers
would be isolated by the libvirt guest AppArmor profile. This issue only
affected Ubuntu 13.10. (CVE-2014-0134)

Mark Heckmann discovered that OpenStack Nova did not enforce RBAC policy
when adding security group rules via the EC2 API. A remote authenticated
user could exploit this to gain unintended access to this API. This issue
only affected Ubuntu 13.10. (CVE-2014-0167)";

  tag_affected = "nova on Ubuntu 14.04 LTS ,
  Ubuntu 13.10 ,
  Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2247-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2247-1/");
  script_summary("Check for the Version of nova");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-nova", ver:"1:2014.1-0ubuntu1.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-nova", ver:"2012.1.3+stable-20130423-e52e6912-0ubuntu1.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"python-nova", ver:"1:2013.2.3-0ubuntu1.2", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
