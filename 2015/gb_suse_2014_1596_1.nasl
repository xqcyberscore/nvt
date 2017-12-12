###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1596_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for docker openSUSE-SU-2014:1596-1 (docker)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850679");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-09-18 10:37:04 +0200 (Fri, 18 Sep 2015)");
  script_cve_id("CVE-2014-6407", "CVE-2014-6408");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for docker openSUSE-SU-2014:1596-1 (docker)");
  script_tag(name: "summary", value: "Check the version of docker");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  docker was updated to version 1.3.2 to fix two security issues.

  These security issues were fixed:
  - Symbolic and hardlink issues leading to privilege escalation
  (CVE-2014-6407).
  - Potential container escalation (CVE-2014-6408).

  There non-security issues were fixed:
  - Fix deadlock in docker ps -f exited=1
  - Fix a bug when --volumes-from references a container that failed to start
  - --insecure-registry now accepts CIDR notation such as 10.1.0.0/16
  - Private registries whose IPs fall in the 127.0.0.0/8 range do no need
  the --insecure-registry flag
  - Skip the experimental registry v2 API when mirroring is enabled
  - Fixed minor packaging issues.");
  script_tag(name: "affected", value: "docker on openSUSE 13.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "openSUSE-SU", value: "2014:1596_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"docker", rpm:"docker~1.3.2~9.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~1.3.2~9.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~1.3.2~9.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~1.3.2~9.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~1.3.2~9.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}