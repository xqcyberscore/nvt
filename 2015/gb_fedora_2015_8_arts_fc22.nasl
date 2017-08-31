###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for arts FEDORA-2015-8
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
  script_oid("1.3.6.1.4.1.25623.1.0.806924");
  script_version("$Revision: 6851 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-04 09:31:24 +0200 (Fri, 04 Aug 2017) $");
  script_tag(name:"creation_date", value:"2015-12-31 05:11:56 +0100 (Thu, 31 Dec 2015)");
  script_cve_id("CVE-2015-7543");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for arts FEDORA-2015-8");
  script_tag(name: "summary", value: "Check the version of arts");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "arts (analog real-time synthesizer) is the
  sound system of KDE 3. The principle of arts is to create/process sound using
  small modules which do certain tasks. These may be create a waveform (oscillators),
  play samples, filter data, add signals, perform effects like delay/flanger/chorus,
  or output the data to the soundcard.
  By connecting all those small modules together, you can perform complex tasks like
  simulating a mixer, generating an instrument or things like  playing a wave file
  with some effects.");

  script_tag(name: "affected", value: "arts on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2015-8");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174717.html");
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
  if ((res = isrpmvuln(pkg:"arts", rpm:"arts~1.5.10~30.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
