###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_3a568adb31_ripright_fc25.nasl 7336 2017-10-04 05:42:02Z asteins $
#
# Fedora Update for ripright FEDORA-2017-3a568adb31
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873415");
  script_version("$Revision: 7336 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-04 07:42:02 +0200 (Wed, 04 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-09-20 12:40:49 +0200 (Wed, 20 Sep 2017)");
  script_cve_id("CVE-2017-14482");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for ripright FEDORA-2017-3a568adb31");
  script_tag(name: "summary", value: "Check the version of ripright");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "RipRight is a minimal CD ripper modeled 
on autorip. It can run as a daemon and will automatically start ripping any CD 
found in the drive after which the disc will be ejected. Ripping is always to 
FLAC lossless audio format with tags taken from the community-maintained 
MusicBrainz lookup service and cover art from Amazon where possible. If a disc 
is unknown to MusicBrainz, the CD will be ejected without ripping and can also 
be optionally rejected if cover art cannot be found.

With RipRight, ripping a CD collection is just a matter of feeding your Linux
PC each CD in turn and waiting while they are ripped. CDs which are
immediately ejected can be checked with the MusicBrainz Picard tool which
allows CD identifiers to be uploaded to the website database. Any errors or
inaccuracies in the database records can also be edited on the MusicBrainz.
");
  script_tag(name: "affected", value: "ripright on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-3a568adb31");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VGFDWBEH5ZSA34JU5F65W265DMT6REZE");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"ripright", rpm:"ripright~0.11~5.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
