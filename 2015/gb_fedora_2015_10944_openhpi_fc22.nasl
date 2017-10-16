###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for openhpi FEDORA-2015-10944
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
  script_oid("1.3.6.1.4.1.25623.1.0.805984");
  script_version("$Revision: 7419 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-13 09:51:30 +0200 (Fri, 13 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-10-07 08:34:50 +0200 (Wed, 07 Oct 2015)");
  script_cve_id("CVE-2015-3248");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for openhpi FEDORA-2015-10944");
  script_tag(name: "summary", value: "Check the version of openhpi");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "OpenHPI is an open source project created
with the intent of providing an implementation of the SA Forum's Hardware
Platform Interface (HPI). HPI provides an abstracted interface to managing
computer hardware, typically for chassis and rack based servers. HPI includes
resource modeling  access to and control over sensor, control, watchdog, and
inventory data associated with resources  abstracted System Event Log interfaces
hardware events and alerts and a managed hot swap interface.

OpenHPI provides a modular mechanism for adding new hardware and device support
easily. Many plug-ins exist in the OpenHPI source tree to provide access to
various types of hardware. This includes, but is not limited to, IPMI based
servers, Blade Center, and machines which export data via sysfs.
");
  script_tag(name: "affected", value: "openhpi on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2015-10944");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-October/168841.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"openhpi", rpm:"openhpi~3.4.0~2.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
