###############################################################################
# OpenVAS Include File
# $Id: os_eol.inc 7633 2017-11-02 14:01:14Z cfischer $
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 7633 $
#
###############################################################################

local_var eol_urls, eol_names, eol_regex, eol_cpes;

eol_urls  = make_array();
eol_names = make_array();
eol_regex = make_array();
eol_cpes  = make_array();

# See gather-package-list.nasl for valid/known linux cpes

# openSUSE Leap (http://en.opensuse.org/Lifetime)
eol_urls['cpe:/o:opensuse_project:leap'] = 'http://en.opensuse.org/Lifetime'; # Starting with 42.2 the correct one is used by the NVD
eol_names['cpe:/o:opensuse_project:leap'] = 'openSUSE Leap';
eol_cpes['cpe:/o:opensuse_project:leap:42.3'] = '2019-01-31';
eol_cpes['cpe:/o:opensuse_project:leap:42.2'] = '2018-01-26';
eol_urls['cpe:/o:novell:leap'] = 'http://en.opensuse.org/Lifetime'; # NVD is currently using a wrong vendor here
eol_names['cpe:/o:novell:leap'] = 'openSUSE Leap';
eol_cpes['cpe:/o:novell:leap:42.1'] = '2017-05-17';

# openSUSE (http://en.opensuse.org/Lifetime)
eol_urls['cpe:/o:novell:opensuse'] = 'http://en.opensuse.org/Lifetime';
eol_names['cpe:/o:novell:opensuse'] = 'openSUSE';
eol_cpes['cpe:/o:novell:opensuse:13.2'] = '2017-01-17';
eol_cpes['cpe:/o:novell:opensuse:13.1'] = '2016-02-03';
eol_cpes['cpe:/o:novell:opensuse:12.3'] = '2015-01-29';
eol_cpes['cpe:/o:novell:opensuse:12.2'] = '2014-01-15';
eol_cpes['cpe:/o:novell:opensuse:12.1'] = '2013-05-15';
eol_cpes['cpe:/o:novell:opensuse:11.4'] = '2012-11-05';
eol_cpes['cpe:/o:novell:opensuse:11.3'] = '2012-01-20';
eol_cpes['cpe:/o:novell:opensuse:11.2'] = '2011-05-12';
eol_cpes['cpe:/o:novell:opensuse:11.1'] = '2010-12-31';
eol_cpes['cpe:/o:novell:opensuse:11.0'] = '2010-06-30';
eol_cpes['cpe:/o:novell:opensuse:10.3'] = '2009-10-31';
eol_cpes['cpe:/o:novell:opensuse:10.2'] = '2008-11-30';

# SUSE Linux (http://en.opensuse.org/Lifetime)
eol_urls['cpe:/o:novell:suse_linux'] = 'http://en.opensuse.org/Lifetime';
eol_names['cpe:/o:novell:suse_linux'] = 'SUSE Linux';
eol_cpes['cpe:/o:novell:suse_linux:10.1'] = '2008-05-31';
eol_cpes['cpe:/o:novell:suse_linux:10.0'] = '2007-11-30';
eol_cpes['cpe:/o:novell:suse_linux:9.3'] = '2007-04-30';
eol_cpes['cpe:/o:novell:suse_linux:9.2'] = '2006-10-31';
eol_cpes['cpe:/o:novell:suse_linux:9.1'] = '2006-06-30';
eol_cpes['cpe:/o:novell:suse_linux:9.0'] = 'unknown';
eol_cpes['cpe:/o:novell:suse_linux:8.2'] = 'unknown';
eol_cpes['cpe:/o:novell:suse_linux:8.1'] = 'unknown';
eol_cpes['cpe:/o:novell:suse_linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:novell:suse_linux:7.3'] = 'unknown';

# SLES (http://www.softpanorama.org/Commercial_linuxes/Suse/sles_life_cycle.shtml)
eol_urls['cpe:/o:suse:linux_enterprise_server'] = 'http://www.softpanorama.org/Commercial_linuxes/Suse/sles_life_cycle.shtml';
eol_names['cpe:/o:suse:linux_enterprise_server'] = 'SUSE Linux Enterprise Server';
eol_cpes['cpe:/o:suse:linux_enterprise_server:10'] = '2016-07-31';
eol_cpes['cpe:/o:suse:linux_enterprise_server:9'] = '2011-07-31';

# Ubuntu (https://wiki.ubuntu.com/Releases)
eol_urls['cpe:/o:canonical:ubuntu_linux'] = 'https://wiki.ubuntu.com/Releases';
eol_names['cpe:/o:canonical:ubuntu_linux'] = 'Ubuntu';
eol_cpes['cpe:/o:canonical:ubuntu_linux:16.10'] = '2017-07-20';
eol_cpes['cpe:/o:canonical:ubuntu_linux:15.10'] = '2016-07-28';
eol_cpes['cpe:/o:canonical:ubuntu_linux:15.04'] = '2016-02-04';
eol_cpes['cpe:/o:canonical:ubuntu_linux:14.10'] = '2014-07-23';
eol_cpes['cpe:/o:canonical:ubuntu_linux:13.10'] = '2014-07-17';
eol_cpes['cpe:/o:canonical:ubuntu_linux:13.04'] = '2014-01-27';
eol_cpes['cpe:/o:canonical:ubuntu_linux:12.10'] = '2014-05-16';
eol_cpes['cpe:/o:canonical:ubuntu_linux:12.04'] = '2017-04-28';
eol_cpes['cpe:/o:canonical:ubuntu_linux:12.04:-:lts'] = '2017-04-28';
eol_cpes['cpe:/o:canonical:ubuntu_linux:11.10'] = '2013-05-09';
eol_cpes['cpe:/o:canonical:ubuntu_linux:11.04'] = '2012-10-28';
eol_cpes['cpe:/o:canonical:ubuntu_linux:10.10'] = '2012-04-10';
eol_cpes['cpe:/o:canonical:ubuntu_linux:10.04'] = '2015-04-30';
eol_cpes['cpe:/o:canonical:ubuntu_linux:10.04:-:lts'] = '2015-04-30';
eol_cpes['cpe:/o:canonical:ubuntu_linux:9.10']  = '2011-04-30';
eol_cpes['cpe:/o:canonical:ubuntu_linux:9.04']  = '2010-10-23';
eol_cpes['cpe:/o:canonical:ubuntu_linux:8.10']  = '2011-05-12';
eol_cpes['cpe:/o:canonical:ubuntu_linux:8.04']  = '2013-05-09';
eol_cpes['cpe:/o:canonical:ubuntu_linux:8.04:-:lts']  = '2013-05-09';
eol_cpes['cpe:/o:canonical:ubuntu_linux:7.10']  = '2009-04-18';
eol_cpes['cpe:/o:canonical:ubuntu_linux:7.04']  = '2008-10-19';
eol_cpes['cpe:/o:canonical:ubuntu_linux:6.10']  = '2008-04-26';
eol_cpes['cpe:/o:canonical:ubuntu_linux:6.06']  = '2009-07-14';
eol_cpes['cpe:/o:canonical:ubuntu_linux:6.06:-:lts']  = '2009-07-14';
eol_cpes['cpe:/o:canonical:ubuntu_linux:5.10']  = '2007-04-13';
eol_cpes['cpe:/o:canonical:ubuntu_linux:5.04']  = '2006-10-31';
eol_cpes['cpe:/o:canonical:ubuntu_linux:4.10']  = '2006-04-30';

# Red Hat Enterprise Linux (https://access.redhat.com/security/updates/eol/)
eol_urls['cpe:/o:redhat:enterprise_linux'] = 'https://access.redhat.com/security/updates/eol/';
eol_names['cpe:/o:redhat:enterprise_linux'] = 'Red Hat Enterprise Linux';
eol_cpes['cpe:/o:redhat:enterprise_linux:4'] = 'unknown';
eol_cpes['cpe:/o:redhat:enterprise_linux:3'] = 'unknown';
eol_cpes['cpe:/o:redhat:enterprise_linux:2.1'] = 'unknown';

# Red Hat Linux (https://en.wikipedia.org/wiki/Red_Hat_Linux#Version_history)
eol_urls['cpe:/o:redhat:linux'] = 'https://en.wikipedia.org/wiki/Red_Hat_Linux#Version_history';
eol_names['cpe:/o:redhat:linux'] = 'Red Hat Linux';
eol_cpes['cpe:/o:redhat:linux:9'] = 'unknown';
eol_cpes['cpe:/o:redhat:linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:redhat:linux:7.3'] = 'unknown';

# CentOS (http://wiki.centos.org/Download)
eol_urls['cpe:/o:centos:centos'] = 'http://wiki.centos.org/Download';
eol_names['cpe:/o:centos:centos'] = 'CentOS';
eol_cpes['cpe:/o:centos:centos:5'] = '2017-03-31';
eol_cpes['cpe:/o:centos:centos:4'] = '2012-02-29';
eol_cpes['cpe:/o:centos:centos:3'] = '2010-10-31';
eol_cpes['cpe:/o:centos:centos:2'] = '2009-05-31';

# Fedora (https://fedoraproject.org/wiki/End_of_life?rd=LifeCycle/EOL)
eol_urls['cpe:/o:fedoraproject:fedora'] = 'https://fedoraproject.org/wiki/End_of_life?rd=LifeCycle/EOL';
eol_names['cpe:/o:fedoraproject:fedora'] = 'Fedora';
eol_cpes['cpe:/o:fedoraproject:fedora:24'] = '2017-08-08';
eol_cpes['cpe:/o:fedoraproject:fedora:23'] = '2016-12-20';
eol_cpes['cpe:/o:fedoraproject:fedora:22'] = '2016-07-19';
eol_cpes['cpe:/o:fedoraproject:fedora:21'] = '2015-12-01';
eol_cpes['cpe:/o:fedoraproject:fedora:20'] = '2015-06-23';
eol_cpes['cpe:/o:fedoraproject:fedora:19'] = '2015-01-06';
eol_cpes['cpe:/o:fedoraproject:fedora:18'] = '2014-01-14';
eol_cpes['cpe:/o:fedoraproject:fedora:17'] = '2013-07-30';
eol_cpes['cpe:/o:fedoraproject:fedora:16'] = '2013-02-12';
eol_cpes['cpe:/o:fedoraproject:fedora:15'] = '2012-06-26';
eol_cpes['cpe:/o:fedoraproject:fedora:14'] = '2011-12-09';
eol_cpes['cpe:/o:fedoraproject:fedora:13'] = '2011-06-24';
eol_cpes['cpe:/o:fedoraproject:fedora:12'] = '2011-02-12';
eol_cpes['cpe:/o:fedoraproject:fedora:11'] = '2010-06-25';
eol_cpes['cpe:/o:fedoraproject:fedora:10'] = '2009-12-19';
eol_cpes['cpe:/o:fedoraproject:fedora:9']  = '2009-07-10';
eol_cpes['cpe:/o:fedoraproject:fedora:8']  = '2009-01-07';
eol_cpes['cpe:/o:fedoraproject:fedora:7']  = '2008-06-13';
eol_urls['cpe:/o:fedoraproject:fedora_core'] = 'https://fedoraproject.org/wiki/End_of_life?rd=LifeCycle/EOL';
eol_names['cpe:/o:fedoraproject:fedora_core'] = 'Fedora Core';
eol_cpes['cpe:/o:fedoraproject:fedora_core:6'] = '2007-12-27';
eol_cpes['cpe:/o:fedoraproject:fedora_core:5'] = '2007-07-02';
eol_cpes['cpe:/o:fedoraproject:fedora_core:4'] = '2006-08-07';
eol_cpes['cpe:/o:fedoraproject:fedora_core:3'] = '2006-01-16';
eol_cpes['cpe:/o:fedoraproject:fedora_core:2'] = '2005-04-11';
eol_cpes['cpe:/o:fedoraproject:fedora_core:1'] = '2004-09-20';

# Debian (https://en.wikipedia.org/wiki/List_of_Debian_releases#Release_table)
eol_urls['cpe:/o:debian:debian_linux'] = 'https://en.wikipedia.org/wiki/List_of_Debian_releases#Release_table';
eol_names['cpe:/o:debian:debian_linux'] = 'Debian GNU/Linux';
eol_cpes['cpe:/o:debian:debian_linux:6.0'] = '2016-02-29';
eol_cpes['cpe:/o:debian:debian_linux:5.0'] = '2012-02-06';
eol_cpes['cpe:/o:debian:debian_linux:4.0'] = '2010-02-15';
eol_cpes['cpe:/o:debian:debian_linux:3.1'] = '2008-03-31';
eol_cpes['cpe:/o:debian:debian_linux:3.0'] = '2006-06-30';
eol_cpes['cpe:/o:debian:debian_linux:2.2'] = '2003-06-30';
eol_cpes['cpe:/o:debian:debian_linux:2.1'] = '2000-10-30';
eol_cpes['cpe:/o:debian:debian_linux:2.0'] = 'unknown';
eol_cpes['cpe:/o:debian:debian_linux:1.3'] = 'unknown';
eol_cpes['cpe:/o:debian:debian_linux:1.2'] = 'unknown';
eol_cpes['cpe:/o:debian:debian_linux:1.1'] = 'unknown';

# Mandriva (https://en.wikipedia.org/wiki/Mandriva_Linux#Table_of_versions)
eol_urls['cpe:/o:mandriva:linux'] = 'https://en.wikipedia.org/wiki/Mandriva_Linux#Table_of_versions';
eol_names['cpe:/o:mandriva:linux'] = 'Mandriva Linux';
eol_cpes['cpe:/o:mandriva:linux:2011.0'] = '2013-02-29';
eol_cpes['cpe:/o:mandriva:linux:2010.2'] = 'unknown';
eol_cpes['cpe:/o:mandriva:linux:2010.1'] = '2012-07-08';
eol_cpes['cpe:/o:mandriva:linux:2010.0'] = '2012-11-03';
eol_cpes['cpe:/o:mandriva:linux:2009.1'] = '2010-10-29';
eol_cpes['cpe:/o:mandriva:linux:2009.0'] = '2011-10-15';
eol_cpes['cpe:/o:mandriva:linux:2008.1'] = '2009-10-15';
eol_cpes['cpe:/o:mandriva:linux:2008.0'] = '2010-10-09';
eol_cpes['cpe:/o:mandriva:linux:2007.1'] = 'unknown';
eol_cpes['cpe:/o:mandriva:linux:2007.0'] = 'unknown';
eol_cpes['cpe:/o:mandriva:linux:2006.0'] = 'unknown';
eol_urls['cpe:/o:mandriva:enterprise_server'] = 'https://en.wikipedia.org/wiki/Mandriva_Linux#Table_of_versions';
eol_names['cpe:/o:mandriva:enterprise_server'] = 'Mandriva Enterprise Server';
eol_cpes['cpe:/o:mandriva:enterprise_server:5.2'] = 'unknown';
eol_cpes['cpe:/o:mandriva:enterprise_server:5.1'] = 'unknown';
eol_cpes['cpe:/o:mandriva:enterprise_server:5.0'] = 'unknown';
eol_cpes['cpe:/o:mandriva:enterprise_server:5'] = 'unknown';

# Mandrake
eol_names['cpe:/o:mandrakesoft:mandrake_linux'] = 'Mandrake Linux';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:10.1'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:10.0'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:9.2'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:9.1'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:9.0'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:8.2'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:8.1'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:7.2'] = 'unknown';

# Mageia (https://en.wikipedia.org/wiki/Mageia#Version_history)
eol_urls['cpe:/o:mageia:linux'] = 'https://en.wikipedia.org/wiki/Mageia#Version_history';
eol_names['cpe:/o:mageia:linux'] = 'Mageia Linux';
eol_cpes['cpe:/o:mageia:linux:6'] = '2019-01-16';
eol_cpes['cpe:/o:mageia:linux:5.1'] = '2017-10-31';
eol_cpes['cpe:/o:mageia:linux:5'] = '2017-10-31';
eol_cpes['cpe:/o:mageia:linux:4.1'] = '2015-09-19';
eol_cpes['cpe:/o:mageia:linux:4'] = '2015-09-19';
eol_cpes['cpe:/o:mageia:linux:3'] = '2014-11-26';
eol_cpes['cpe:/o:mageia:linux:2'] = '2013-11-22';
eol_cpes['cpe:/o:mageia:linux:1'] = '2012-11-01';

# Slackware (https://en.wikipedia.org/wiki/Slackware#Releases)
eol_urls['cpe:/o:slackware:slackware_linux'] = 'https://en.wikipedia.org/wiki/Slackware#Releases';
eol_names['cpe:/o:slackware:slackware_linux'] = 'Slackware Linux';
eol_cpes['cpe:/o:slackware:slackware_linux:12.2'] = '2013-12-09';
eol_cpes['cpe:/o:slackware:slackware_linux:12.1'] = '2013-12-09';
eol_cpes['cpe:/o:slackware:slackware_linux:12.0'] = '2012-02-01';
eol_cpes['cpe:/o:slackware:slackware_linux:11.0'] = '2012-02-01';
eol_cpes['cpe:/o:slackware:slackware_linux:10.2'] = '2012-02-01';
eol_cpes['cpe:/o:slackware:slackware_linux:10.1'] = '2012-02-01';
eol_cpes['cpe:/o:slackware:slackware_linux:10.0'] = '2012-02-01';
eol_cpes['cpe:/o:slackware:slackware_linux:9.1'] = '2012-02-01';
eol_cpes['cpe:/o:slackware:slackware_linux:9.0'] = '2012-02-01';
eol_cpes['cpe:/o:slackware:slackware_linux:8.1'] = '2012-02-01';
eol_cpes['cpe:/o:slackware:slackware_linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:7.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:7.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:4.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.9'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.6'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.5'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.4'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.3'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.2'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:2.3'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:2.2'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:2.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:2.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:1.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:1.00'] = 'unknown';

# Connectiva Linux (https://de.wikipedia.org/wiki/Conectiva#Versionen)
eol_urls['cpe:/a:connectiva:linux'] = 'https://de.wikipedia.org/wiki/Conectiva#Versionen';
eol_names['cpe:/a:connectiva:linux'] = 'Connectiva Linux';
eol_cpes['cpe:/a:connectiva:linux:10.0'] = 'unknown';
eol_cpes['cpe:/a:connectiva:linux:9.0'] = 'unknown';

# Univention Corporate Server (http://wiki.univention.de/index.php?title=Maintenance_Cycle_for_UCS)
eol_urls['cpe:/o:univention:univention_corporate_server'] = 'http://wiki.univention.de/index.php?title=Maintenance_Cycle_for_UCS';
eol_names['cpe:/o:univention:univention_corporate_server'] = 'Univention Corporate Server (UCS)';
eol_cpes['cpe:/o:univention:univention_corporate_server:4.1'] = '2018-04-30';
eol_cpes['cpe:/o:univention:univention_corporate_server:4.0'] = '2016-05-31';
eol_cpes['cpe:/o:univention:univention_corporate_server:3.3'] = '2016-12-31';
eol_cpes['cpe:/o:univention:univention_corporate_server:3.2'] = '2016-11-30';
eol_cpes['cpe:/o:univention:univention_corporate_server:3.1'] = '2014-05-31';
eol_cpes['cpe:/o:univention:univention_corporate_server:3.0'] = '2013-06-30';
eol_cpes['cpe:/o:univention:univention_corporate_server:2.4'] = '2013-12-31';
eol_cpes['cpe:/o:univention:univention_corporate_server:2.3'] = 'unknown';
eol_cpes['cpe:/o:univention:univention_corporate_server:2.2'] = 'unknown';
eol_cpes['cpe:/o:univention:univention_corporate_server:2.1'] = 'unknown';
eol_cpes['cpe:/o:univention:univention_corporate_server:2.0'] = 'unknown';

# Trustix
eol_urls['cpe:/o:trustix:secure_linux'] = 'https://en.wikipedia.org/wiki/Trustix';
eol_names['cpe:/o:trustix:secure_linux'] = 'Trustix';
eol_cpes['cpe:/o:trustix:secure_linux:3.0.5'] = '2007-12-31';
eol_cpes['cpe:/o:trustix:secure_linux:3.0'] = '2007-12-31';
eol_cpes['cpe:/o:trustix:secure_linux:2.2'] = '2007-12-31';
eol_cpes['cpe:/o:trustix:secure_linux:2.1'] = '2007-12-31';
eol_cpes['cpe:/o:trustix:secure_linux:2.0'] = '2007-12-31';
eol_cpes['cpe:/o:trustix:secure_linux:1.5'] = '2007-12-31';
eol_cpes['cpe:/o:trustix:secure_linux:1.2'] = '2007-12-31';
eol_cpes['cpe:/o:trustix:secure_linux:1.1'] = '2007-12-31';

# HP-UX
eol_urls['cpe:/o:hp:hp-ux'] = 'https://ssl.www8.hp.com/h20195/V2/GetDocument.aspx?docname=4AA4-7673ENW&cc=us&lc=en';
eol_names['cpe:/o:hp:hp-ux'] = 'HP-UX';
eol_cpes['cpe:/o:hp:hp-ux:11.00'] = '2006-12-31';
eol_cpes['cpe:/o:hp:hp-ux:10.30'] = 'unknown';
eol_cpes['cpe:/o:hp:hp-ux:10.26'] = 'unknown';
eol_cpes['cpe:/o:hp:hp-ux:10.24'] = 'unknown';
eol_cpes['cpe:/o:hp:hp-ux:10.20'] = '2003-06-30';
eol_cpes['cpe:/o:hp:hp-ux:10.10'] = 'unknown';
eol_cpes['cpe:/o:hp:hp-ux:10.01'] = 'unknown';

# FortiOS (https://www.boll.ch/fortinet/assets/LifeCycleStatus.pdf)
eol_urls['cpe:/o:fortinet:fortios'] = 'https://www.boll.ch/fortinet/assets/LifeCycleStatus.pdf';
eol_names['cpe:/o:fortinet:fortios'] = 'FortiOS';
eol_cpes['cpe:/o:fortinet:fortios:5.4'] = '2020-06-21';
eol_cpes['cpe:/o:fortinet:fortios:5.2'] = '2018-12-13';
eol_cpes['cpe:/o:fortinet:fortios:5.0'] = '2017-05-01';
eol_cpes['cpe:/o:fortinet:fortios:4.3'] = '2014-03-19';
eol_cpes['cpe:/o:fortinet:fortios:4.2'] = '2013-04-01';
eol_cpes['cpe:/o:fortinet:fortios:4.1'] = '2012-08-24';
eol_cpes['cpe:/o:fortinet:fortios:4.0'] = '2012-02-24';
eol_cpes['cpe:/o:fortinet:fortios:3.7'] = '2011-07-18';
eol_cpes['cpe:/o:fortinet:fortios:3.6'] = '2011-02-04';
eol_cpes['cpe:/o:fortinet:fortios:3.5'] = '2010-07-03';
eol_cpes['cpe:/o:fortinet:fortios:3.4'] = '2009-12-29';
eol_cpes['cpe:/o:fortinet:fortios:3.3'] = '2009-10-02';

# Xenserver (https://www.citrix.de/support/product-lifecycle/product-matrix.html)
eol_urls['cpe:/a:citrix:xenserver'] = 'https://www.citrix.de/support/product-lifecycle/product-matrix.html';
eol_names['cpe:/a:citrix:xenserver'] = 'Xenserver';
eol_cpes['cpe:/a:citrix:xenserver:7.2'] = '2018-03-16';
eol_cpes['cpe:/a:citrix:xenserver:7.0'] = '2021-05-19';
eol_cpes['cpe:/a:citrix:xenserver:6.5'] = '2018-06-26';
eol_cpes['cpe:/a:citrix:xenserver:6.2'] = '2018-06-26';
eol_cpes['cpe:/a:citrix:xenserver:6.1'] = '2016-09-30';
eol_cpes['cpe:/a:citrix:xenserver:6.0.2'] = '2018-06-26';
eol_cpes['cpe:/a:citrix:xenserver:6.0.0'] = '2016-09-26';
eol_cpes['cpe:/a:citrix:xenserver:5.6'] = '2014-03-31';
eol_cpes['cpe:/a:citrix:xenserver:5.5'] = '2013-09-15';
eol_cpes['cpe:/a:citrix:xenserver:5.0'] = '2013-09-15';

# Cisco IOS XR (http://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xr-software/eos-eol-notice-listing.html)
eol_urls['cpe:/o:cisco:ios_xr'] = 'http://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xr-software/eos-eol-notice-listing.html';
eol_names['cpe:/o:cisco:ios_xr'] = 'Cisco IOS XR';
eol_cpes['cpe:/o:cisco:ios_xr:5.3'] = '2019-08-11';
eol_cpes['cpe:/o:cisco:ios_xr:5.2'] = '2019-01-29';
eol_cpes['cpe:/o:cisco:ios_xr:5.1'] = '2018-04-01';
eol_cpes['cpe:/o:cisco:ios_xr:5.0'] = '2018-03-15';
eol_cpes['cpe:/o:cisco:ios_xr:4.3'] = '2017-10-10';
eol_cpes['cpe:/o:cisco:ios_xr:4.2'] = '2016-02-15';
eol_cpes['cpe:/o:cisco:ios_xr:4.1'] = '2016-03-19';
eol_cpes['cpe:/o:cisco:ios_xr:4.0'] = '2014-10-01';
eol_cpes['cpe:/o:cisco:ios_xr:3.9'] = '2012-04-09';
eol_cpes['cpe:/o:cisco:ios_xr:3.8'] = '2013-12-28';
eol_cpes['cpe:/o:cisco:ios_xr:3.6'] = '2012-06-30';
eol_cpes['cpe:/o:cisco:ios_xr:3.5'] = '2012-05-11';
eol_cpes['cpe:/o:cisco:ios_xr:3.4'] = '2011-12-31';
eol_cpes['cpe:/o:cisco:ios_xr:3.3'] = '2011-12-31';
eol_cpes['cpe:/o:cisco:ios_xr:3.2'] = '2008-04-29';

# FreeBSD (https://www.freebsd.org/security/unsupported.html)
eol_urls['cpe:/o:freebsd:freebsd'] = 'https://www.freebsd.org/security/unsupported.html';
eol_names['cpe:/o:freebsd:freebsd'] = 'FreeBSD';
eol_cpes['cpe:/o:freebsd:freebsd:4'] = '2007-01-31';
eol_cpes['cpe:/o:freebsd:freebsd:4.11'] = '2007-01-31';
eol_cpes['cpe:/o:freebsd:freebsd:5'] = '2008-05-31';
eol_cpes['cpe:/o:freebsd:freebsd:5.3'] = '2006-10-31';
eol_cpes['cpe:/o:freebsd:freebsd:5.4'] = '2006-10-31';
eol_cpes['cpe:/o:freebsd:freebsd:5.5'] = '2008-05-31';
eol_cpes['cpe:/o:freebsd:freebsd:6'] = '2010-11-30';
eol_cpes['cpe:/o:freebsd:freebsd:6.0'] = '2007-01-31';
eol_cpes['cpe:/o:freebsd:freebsd:6.1'] = '2008-05-31';
eol_cpes['cpe:/o:freebsd:freebsd:6.2'] = '2008-05-31';
eol_cpes['cpe:/o:freebsd:freebsd:6.3'] = '2010-01-31';
eol_cpes['cpe:/o:freebsd:freebsd:6.4'] = '2010-11-30';
eol_cpes['cpe:/o:freebsd:freebsd:7'] = '2013-02-28';
eol_cpes['cpe:/o:freebsd:freebsd:7.0'] = '2009-04-30';
eol_cpes['cpe:/o:freebsd:freebsd:7.1'] = '2011-02-28';
eol_cpes['cpe:/o:freebsd:freebsd:7.2'] = '2010-06-30';
eol_cpes['cpe:/o:freebsd:freebsd:7.3'] = '2012-03-31';
eol_cpes['cpe:/o:freebsd:freebsd:7.4'] = '2013-02-28';
eol_cpes['cpe:/o:freebsd:freebsd:8'] = '2015-08-01';
eol_cpes['cpe:/o:freebsd:freebsd:8.0'] = '2010-11-30';
eol_cpes['cpe:/o:freebsd:freebsd:8.1'] = '2012-07-31';
eol_cpes['cpe:/o:freebsd:freebsd:8.2'] = '2012-07-31';
eol_cpes['cpe:/o:freebsd:freebsd:8.3'] = '2014-04-30';
eol_cpes['cpe:/o:freebsd:freebsd:8.4'] = '2015-08-01';
eol_cpes['cpe:/o:freebsd:freebsd:9'] = '2016-12-31';
eol_cpes['cpe:/o:freebsd:freebsd:9.0'] = '2013-03-31';
eol_cpes['cpe:/o:freebsd:freebsd:9.1'] = '2014-12-31';
eol_cpes['cpe:/o:freebsd:freebsd:9.2'] = '2014-12-31';
eol_cpes['cpe:/o:freebsd:freebsd:9.3'] = '2016-12-31';
# eol_cpes['cpe:/o:freebsd:freebsd:10.0'] = '2015-02-28'; # nb: Don't add 10.0 for now as gb_ssh_os_detection.nasl can't detect the differences between 10.x and would throw false positives
eol_cpes['cpe:/o:freebsd:freebsd:10.1'] = '2016-12-31';
eol_cpes['cpe:/o:freebsd:freebsd:10.2'] = '2016-12-31';

# NetBSD (https://en.wikipedia.org/wiki/NetBSD#Releases)
eol_urls['cpe:/o:netbsd:netbsd'] = 'https://en.wikipedia.org/wiki/NetBSD#Releases';
eol_names['cpe:/o:netbsd:netbsd'] = 'NetBSD';
eol_cpes['cpe:/o:netbsd:netbsd:0.8'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:0.9'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.0'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.1'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.2'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.3'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.4'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.5'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.6'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:2.0'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:3.0'] = '2009-05-30';
eol_cpes['cpe:/o:netbsd:netbsd:4.0'] = '2012-11-17';
eol_cpes['cpe:/o:netbsd:netbsd:5.0'] = '2015-11-09';

# OpenBSD (https://en.wikipedia.org/wiki/OpenBSD_version_history)
eol_urls['cpe:/o:openbsd:openbsd'] = 'https://en.wikipedia.org/wiki/OpenBSD_version_history';
eol_names['cpe:/o:openbsd:openbsd'] = 'OpenBSD';
eol_cpes['cpe:/o:openbsd:openbsd:1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:1.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:1.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.0'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.3'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.4'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.5'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.6'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.7'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.8'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.9'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.0'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.3'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.4'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.5'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.6'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.7'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.8'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.9'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.0'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.3'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.4'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.5'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.6'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.7'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.8'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.9'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:5'] = '2017-04-11';
eol_cpes['cpe:/o:openbsd:openbsd:5.0'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:5.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:5.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:5.3'] = '2014-05-01';
eol_cpes['cpe:/o:openbsd:openbsd:5.4'] = '2014-11-01';
eol_cpes['cpe:/o:openbsd:openbsd:5.5'] = '2015-05-01';
eol_cpes['cpe:/o:openbsd:openbsd:5.6'] = '2015-10-18';
eol_cpes['cpe:/o:openbsd:openbsd:5.7'] = '2016-03-29';
eol_cpes['cpe:/o:openbsd:openbsd:5.8'] = '2016-09-01';
eol_cpes['cpe:/o:openbsd:openbsd:5.9'] = '2017-04-11';
eol_cpes['cpe:/o:openbsd:openbsd:6.0'] = '2017-10-09';

# Greenbone OS (https://www.greenbone.net/roadmap-lifecycle/#tab-id-6)
# 3.0+ have patchlevels like 3.0.39
# 2.2.0 and below has patchlevels like 2.2.0-37
eol_urls['cpe:/o:greenbone:greenbone_os'] = 'https://www.greenbone.net/roadmap-lifecycle/#tab-id-6';
eol_names['cpe:/o:greenbone:greenbone_os'] = 'Greenbone OS';
eol_regex['cpe:/o:greenbone:greenbone_os'] = '^([0-9]+\\.[0-9]+)';
eol_cpes['cpe:/o:greenbone:greenbone_os:4.0'] = '2017-07-30';
eol_cpes['cpe:/o:greenbone:greenbone_os:3.0'] = '2015-10-03';
eol_cpes['cpe:/o:greenbone:greenbone_os:2.2'] = '2016-01-03';
eol_cpes['cpe:/o:greenbone:greenbone_os:2.1'] = '2014-05-31';
eol_cpes['cpe:/o:greenbone:greenbone_os:2.0'] = '2014-01-31';
eol_cpes['cpe:/o:greenbone:greenbone_os:1.7'] = '2013-06-30';
eol_cpes['cpe:/o:greenbone:greenbone_os:1.6'] = 'unknown';

# General notes for windows: https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet

#Windows for Workgroups 3.1 (https://support.microsoft.com/en-us/lifecycle/?p1=3127)
eol_urls['cpe:/o:microsoft:windows:3.1'] = 'https://support.microsoft.com/en-us/lifecycle/?p1=3127';
eol_names['cpe:/o:microsoft:windows'] = 'Windows for Workgroups 3.1/3.11';
eol_cpes['cpe:/o:microsoft:windows:3.1'] = '2001-12-31';

#Windows for Workgroups 3.11 (https://support.microsoft.com/en-us/lifecycle/?p1=3128)
eol_urls['cpe:/o:microsoft:windows:3.11'] = 'https://support.microsoft.com/en-us/lifecycle/?p1=3128';
eol_cpes['cpe:/o:microsoft:windows:3.11'] = '2001-12-31';

#Windows 95 (https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+95&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_95'] = 'https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+95&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_95'] = 'Windows 95';
eol_cpes['cpe:/o:microsoft:windows_95'] = '2001-12-31';
eol_cpes['cpe:/o:microsoft:windows_95::gold'] = '2001-12-31';
eol_cpes['cpe:/o:microsoft:windows_95::osr2'] = '2001-12-31';
eol_cpes['cpe:/o:microsoft:windows_95::osr2.1'] = '2001-12-31';
eol_cpes['cpe:/o:microsoft:windows_95::osr2.5'] = '2001-12-31';
eol_cpes['cpe:/o:microsoft:windows_95::sp1'] = '2001-12-31';
eol_cpes['cpe:/o:microsoft:windows_95::sr2'] = '2001-12-31';

#Windows 98 (https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+98&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_98'] = 'https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+98&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_98'] = 'Windows 98';
eol_cpes['cpe:/o:microsoft:windows_98'] = '2006-07-11';
eol_cpes['cpe:/o:microsoft:windows_98::beta'] = '2006-07-11';
eol_cpes['cpe:/o:microsoft:windows_98::gold'] = '2006-07-11';
eol_cpes['cpe:/o:microsoft:windows_98::scd'] = '2006-07-11';
eol_cpes['cpe:/o:microsoft:windows_98:beta'] = '2006-07-11';
eol_cpes['cpe:/a:microsoft:windows_98_plus_pack'] = '2006-07-11';
eol_cpes['cpe:/o:microsoft:windows_98se'] = '2006-07-11';

#Windows Millennium Edition (httpen-us://support.microsoft.com/en-us/lifecycle/?p1=6519)
eol_cpes['cpe:/o:microsoft:windows_me'] = 'httpen-us://support.microsoft.com/en-us/lifecycle/?p1=6519';
eol_names['cpe:/o:microsoft:windows_me'] = 'Windows Millennium Edition';
eol_cpes['cpe:/o:microsoft:windows_me'] = '2006-07-11';
eol_cpes['cpe:/o:microsoft:windows_me::gold'] = '2006-07-11';

#Windows NT (https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+NT&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_nt'] = 'https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+NT&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_nt'] = 'Windows NT';
eol_cpes['cpe:/o:microsoft:windows_nt:3.0.1'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:3.1'] = '2000-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1'] = '2000-09-30';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp1'] = '2000-09-30';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp2'] = '2000-09-30';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp3'] = '2000-09-30';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp4'] = '2000-09-30';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp5'] = '2000-09-30';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp5:alpha'] = '2000-09-30';
eol_cpes['cpe:/o:microsoft:windows_nt:3.51'] = '2000-09-30';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:embedded'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:enterprise'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:terminal_server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:workstation'] = '2002-06-30';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:embedded'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:enterprise'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:terminal_server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:workstation'] = '2002-06-30';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:embedded'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:enterprise'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:terminal_server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:workstation'] = '2002-06-30';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:embedded'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:enterprise'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:terminal_server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:workstation'] = '2002-06-30';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:embedded'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:enterprise'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:terminal_server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:workstation'] = '2002-06-30';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:embedded'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:enterprise'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:terminal_server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:workstation'] = '2002-06-30';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:embedded'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:enterprise'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:terminal_server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:workstation'] = '2002-06-30';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:embedded'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:enterprise'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:terminal_server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:workstation'] = '2002-06-30';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:embedded'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:enterprise'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:terminal_server'] = '2002-12-31';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:workstation'] = '2002-06-30';

#Windows 2000 (https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+2000&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_2000'] = 'https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+2000&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_2000'] = 'Windows 2000';
eol_cpes['cpe:/o:microsoft:windows_2000'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::beta3'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::gold'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:advanced_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:datacenter_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:professional'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::rc1'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::rc2'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:advanced_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:datacenter_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:professional'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:advanced_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:datacenter_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:professional'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:advanced_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:datacenter_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:professional'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:advanced_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:datacenter_server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:professional'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:server'] = '2010-07-13';
eol_cpes['cpe:/o:microsoft:windows_2000:beta3'] = '2010-07-13';

#Windows XP (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20XP&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_xp'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20XP&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_xp'] = 'Windows XP';
eol_cpes['cpe:/o:microsoft:windows_xp'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:::x64'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:::x86'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::gold'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::gold:embedded'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::gold:media_center'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::gold:professional'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::gold:tablet_pc'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1:embedded'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1:media_center'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1:professional'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1:tablet_pc'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:embedded'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:media_center'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:professional'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:tablet_pc'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:x86'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp3'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp::sp3:x86'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:gold:64-bit-2002'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:gold:64-bit-2003'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:gold:home'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:gold:x64'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp1:home'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp1:x64'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp2:home'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp2:x64'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:embedded'] = '2016-01-12';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:home'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:media_center'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:professional'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:tablet_pc'] = '2014-04-08';
eol_cpes['cpe:/o:microsoft:windows_xp:sp3:unknown:english'] = '2014-04-08';

#Windows 2003 (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20Server%202003&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_2003_server'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20Server%202003&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_2003_server'] = 'Windows Server 2003';
eol_cpes['cpe:/o:microsoft:windows_2003_server'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:compute_cluster'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:datacenter'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:enterprise'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:itanium'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:standard'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:storage'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:x64'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:x64-datacenter'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:x64-enterprise'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:x64-standard'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:compute_cluster'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:datacenter'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:enterprise'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:standard'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:storage'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:x64'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:x64-datacenter'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:x64-enterprise'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:x64-standard'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:compute_cluster'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:datacenter'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:enterprise'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:itanium'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:standard'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:storage'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:x64'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:compute_cluster'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:datacenter'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:enterprise'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:itanium'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:standard'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:storage'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:x64'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_2003_server:-:r2_sp2'] = '2015-07-14';

#Windows 2003 (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20Server%202003&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_server_2003'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20Server%202003&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_server_2003'] = 'Windows Server 2003';
eol_cpes['cpe:/o:microsoft:windows_server_2003:::x64'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_server_2003::sp2'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_server_2003::sp2:itanium'] = '2015-07-14';
eol_cpes['cpe:/o:microsoft:windows_server_2003::sp2:x64'] = '2015-07-14';

#Windows 7 (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%207&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_7'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%207&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_7'] = 'Windows 7';
eol_cpes['cpe:/o:microsoft:windows_7:-:-:x32'] = '2013-04-09';
eol_cpes['cpe:/o:microsoft:windows_7:::x32'] = '2013-04-09';
eol_cpes['cpe:/o:microsoft:windows_7:-:-:x64'] = '2013-04-09';
eol_cpes['cpe:/o:microsoft:windows_7:::x64'] = '2013-04-09';
eol_cpes['cpe:/o:microsoft:windows_7:-:-:'] = '2013-04-09';
eol_cpes['cpe:/o:microsoft:windows_7:::'] = '2013-04-09';

#Windows 8 (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%208&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_8'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%208&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_8'] = 'Windows 8';
eol_cpes['cpe:/o:microsoft:windows_8'] = '2016-01-12';
eol_cpes['cpe:/o:microsoft:windows_8:-:-:x86'] = '2016-01-12';
eol_cpes['cpe:/o:microsoft:windows_8:-:sp1:x86'] = '2016-01-12';
eol_cpes['cpe:/o:microsoft:windows_8:-:-:x64'] = '2016-01-12';
eol_cpes['cpe:/o:microsoft:windows_8:-:sp1:x64'] = '2016-01-12';

#Windows Vista (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%20Vista&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_vista'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%20Vista&Filter=FilterNO';
eol_names['cpe:/o:microsoft:windows_vista'] = 'Windows Vista';
eol_cpes['cpe:/o:microsoft:windows_vista'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp1'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp2'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:-:-:x86'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:-:-:x64'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp1:x86'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp2:x86'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp1:x64'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp2:x64'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::gold'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:::x86'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:::x64'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:::x86-enterprise'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:::x86-ultimate'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:::x64-enterprise'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista:::x64-ultimate'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x86'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x64'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x86-enterprise'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x86-ultimate'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x64-enterprise'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x64-ultimate'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x64-home_premium'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp2'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp2:x86'] = '2017-04-11';
eol_cpes['cpe:/o:microsoft:windows_vista::sp2:x64'] = '2017-04-11';

#Windows 10 (https://support.microsoft.com/en-US/help/13853/windows-lifecycle-fact-sheet)
eol_urls['cpe:/o:microsoft:windows_10'] = 'https://support.microsoft.com/en-US/help/13853/windows-lifecycle-fact-sheet';
eol_names['cpe:/o:microsoft:windows_10'] = 'Windows 10';
eol_cpes['cpe:/o:microsoft:windows_10:1507'] = '2017-05-09';
eol_cpes['cpe:/o:microsoft:windows_10:1511'] = '2017-10-10';
#eol_cpes['cpe:/o:microsoft:windows_10:1607'] = '2018-03-01'; # Tentatively March 2018
#eol_cpes['cpe:/o:microsoft:windows_10:1703'] = '2018-09-01'; # Tentatively September 2018
#eol_cpes['cpe:/o:microsoft:windows_10:1709'] = '2019-03-01'; # Tentatively March 2019

function os_reached_eol( cpe, debug ) {

  local_var cpe, debug, base_cpe, pattern, v, version, final_cpe;

  if( ! cpe ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#os_reached_eol" );
    return;
  }

  base_cpe = get_base_cpe( cpe:cpe );

  if( ! array_key_exist( key:base_cpe, array:eol_cpes, part_match:TRUE ) ) {
    if( debug ) display( "DEBUG: Base CPE " + base_cpe + " not in eol_cpes array." );
    set_kb_item( name:"nvt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#Base CPE '" + base_cpe + "' passed to cpe parameter of os_reached_eol is not in the list of EOL products" );
    return;
  }

  # This allows to check for partial matches
  if( eol_regex[base_cpe] ) {
    if( debug ) display( "DEBUG: Base CPE " + base_cpe + " found in eol_regex array." );
    pattern = eol_regex[base_cpe];
    version = get_version_from_cpe( cpe:cpe );
    v = eregmatch( pattern:pattern, string:version );
    if( isnull( v[0] ) ) {
      if( debug ) display( "DEBUG: Passed eol_regex: " + pattern + " doesn't match version in CPE: " + cpe + " ." );
      return;
    } else {
      final_cpe = base_cpe + ":" + v[0];
      if( debug ) display( "DEBUG: Final CPE to check agains EOL versions: " + final_cpe + " ." );
    }
  # Full match for a CPE
  } else {
    if( debug ) display( "DEBUG: Base CPE " + base_cpe + " not found in eol_regex array. Assuming a full match for the CPE " + cpe + " ." );
    final_cpe = cpe;
  }

  if( eol_cpes[final_cpe] && eol_date_reached( eol_date:eol_cpes[final_cpe] ) ) return TRUE;

  return;
}

function get_eol_url( cpe ) {

  local_var cpe, _cpe;

  if( ! cpe ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_eol_url" );
    return FALSE;
  }

  if( eol_urls[cpe] ) # for some windows cpes
    return eol_urls[cpe];

  _cpe = split( cpe, sep:":", keep:FALSE );

  if( _cpe && _cpe[0] && _cpe[1] && _cpe[2] && _cpe[3] ) {
    cpe = _cpe[0] + ':' + _cpe[1] + ':' + _cpe[2] + ':' + _cpe[3];
  }

  if( ! eol_urls[cpe] ) return FALSE;

  return eol_urls[cpe];
}

function get_eol_date( cpe ) {

  local_var cpe, eol_date;

  if( ! cpe ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_eol_date" );
    return FALSE;
  }

  if( ! eol_cpes[cpe] ) return FALSE;

  eol_date = eol_cpes[cpe];

  if( "unknown" >< eol_date ) return FALSE;

  return eol_date;
}

function get_eol_name( cpe ) {

  local_var cpe, _cpe;

  if( ! cpe ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_eol_name" );
    return FALSE;
  }

  if( eol_names[cpe] ) # for some windows cpes
    return eol_names[cpe];

  _cpe = split( cpe, sep:":", keep:FALSE );

  if( _cpe && _cpe[0] && _cpe[1] && _cpe[2] && _cpe[3] ) {
    cpe = _cpe[0] + ':' + _cpe[1] + ':' + _cpe[2] + ':' + _cpe[3];
  }

  if( ! eol_names[cpe] ) return FALSE;

  return eol_names[cpe];
}

function get_eol_version( cpe ) {

  local_var cpe, base_cpe, pattern, version, v;

  if( ! cpe ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_eol_version" );
    return FALSE;
  }

  base_cpe = get_base_cpe( cpe:cpe );
  if( ! eol_regex[base_cpe] ) return FALSE;

  pattern = eol_regex[base_cpe];
  version = get_version_from_cpe( cpe:cpe );
  v = eregmatch( pattern:pattern, string:version );
  if( isnull( v[0] ) ) return FALSE;

  return v[0];
}