/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Ha Thach (tinyusb.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dhserver.h"
#include "dnserver.h"
#include "lwip/init.h"
#include "lwip/timeouts.h"

#include "lwip/pbuf.h"
#include "lwip/udp.h"

#include "bsp/board.h"
#include "pico/stdlib.h"
#include "tusb.h"
#include "usb_descriptors.h"

#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#include "lwip/apps/lwiperf.h"
#include "pico/util/queue.h"
//#include "pico/multicore.h"
#if TU_CHECK_MCU(ESP32S2) || TU_CHECK_MCU(ESP32S3)
// ESP-IDF need "freertos/" prefix in include path.
// CFG_TUSB_OS_INC_PATH should be defined accordingly.
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#else
#include "FreeRTOS.h"
#include "semphr.h"
#include "queue.h"
#include "task.h"
#include "timers.h"
#endif

//#include "ssi.h"
//#include "cgi.h"
//#include "lwip/apps/httpd.h"


// static task for usbd
#if CFG_TUSB_DEBUG
#define USBD_STACK_SIZE (3 * configMINIMAL_STACK_SIZE )
#else
#define USBD_STACK_SIZE (3 * configMINIMAL_STACK_SIZE )
#endif

TaskHandle_t usb_device_taskdef;

// static task for hid
#define HID_STACK_SZIE 2*configMINIMAL_STACK_SIZE
TaskHandle_t hid_taskdef;
TaskHandle_t wifi_maindef;
UBaseType_t uxCoreAffinityMask;

#define QSIZE 16
static queue_t qinbound;

typedef void(* tcpip_init_done_fn) (void *arg);
SemaphoreHandle_t  wifi_scan_info_mutex;
SemaphoreHandle_t  wifi_connection_set;
bool wifi_scanning_switched_on = true;
void usb_device_task(void *param);
void hid_task(void *params);
void main_task(void *params);
int handle_data(int fd, fd_set *ptr);
void tcpip_init	(tcpip_init_done_fn 	initfunc,void *arg);
/* lwip context */
static struct netif netif_data;

/* shared between tud_network_recv_cb() and service_traffic() */
static struct pbuf *received_frame;

/* this is used by this code, ./class/net/net_driver.c, and usb_descriptors.c */
/* ideally speaking, this should be generated from the hardware's unique ID (if available) */
/* it is suggested that the first byte is 0x02 to indicate a link-local address */
const uint8_t tud_network_mac_address[6] = {0x02, 0x02, 0x84, 0x6A, 0x96, 0x00};

/* network parameters of this MCU */
static const ip_addr_t ipaddr = IPADDR4_INIT_BYTES(192, 168, 7, 1);
static const ip_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
static const ip_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);

/* database IP addresses that can be offered to the host; this must be in RAM to store assigned MAC addresses */
static dhcp_entry_t entries[] =
    {
        /* mac ip address                          lease time */
        {{0}, IPADDR4_INIT_BYTES(192, 168, 7, 2), 24 * 60 * 60},
        {{0}, IPADDR4_INIT_BYTES(192, 168, 7, 3), 24 * 60 * 60},
        {{0}, IPADDR4_INIT_BYTES(192, 168, 7, 4), 24 * 60 * 60},
};

static const dhcp_config_t dhcp_config =
    {
        .router = IPADDR4_INIT_BYTES(0, 0, 0, 0),  /* router address (if any) */
        .port = 67,                                /* listen port */
        .dns = IPADDR4_INIT_BYTES(192, 168, 7, 1), /* dns server (if any) */
        "usb",                                     /* dns suffix */
        TU_ARRAY_SIZE(entries),                    /* num entry */
        entries                                    /* entries */
};
static err_t linkoutput_fn(struct netif *netif, struct pbuf *p)
{
  (void)netif;

  for (;;)
  {
    /* if TinyUSB isn't ready, we must signal back to lwip that there is nothing we can do */
    if (!tud_ready())
      return ERR_USE;

    /* if the network driver can accept another packet, we make it happen */
    if (tud_network_can_xmit(p->tot_len))
    {
      tud_network_xmit(p, 0 /* unused for this example */);
      return ERR_OK;
    }

    /* transfer execution to TinyUSB in the hopes that it will finish transmitting the prior packet */
    tud_task();
  }
}

static err_t output_fn(struct netif *netif, struct pbuf *p, const ip_addr_t *addr)
{
  return etharp_output(netif, p, addr);
}


static err_t netif_init_cb(struct netif *netif)
{
  LWIP_ASSERT("netif != NULL", (netif != NULL));
  netif->mtu = CFG_TUD_NET_MTU;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;
  netif->state = NULL;
  netif->name[0] = 'E';
  netif->name[1] = 'X';
  netif->linkoutput = linkoutput_fn;
  netif->output = output_fn;
  return ERR_OK;
}

static void init_lwip(void)
{
  lwip_init();
  struct netif *netif = &netif_data;
  /* the lwip virtual MAC address must be different from the host's; to ensure this, we toggle the LSbit */
  netif->hwaddr_len = sizeof(tud_network_mac_address);
  memcpy(netif->hwaddr, tud_network_mac_address, sizeof(tud_network_mac_address));
  netif->hwaddr[5] ^= 0x01;
  netif = netif_add(netif, &ipaddr, &netmask, &gateway, NULL, netif_init_cb, ip_input);
  netif_set_default(netif);
}

/* handle any DNS requests from dns-server */
bool dns_query_proc(const char *name, ip_addr_t *addr)
{
  if (0 == strcmp(name, "tiny.usb"))
  {
    *addr = ipaddr;
    return true;
  }
  return false;
}

bool tud_network_recv_cb(const uint8_t *src, uint16_t size)
{
  /* this shouldn't happen, but if we get another packet before
  parsing the previous, we must signal our inability to accept it */
  if (received_frame)
    return false;

  if (size)
  {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, size, PBUF_POOL);

    if (p)
    {
      /* pbuf_alloc() has already initialized struct; all we need to do is copy the data */
      memcpy(p->payload, src, size);

      /* store away the pointer for service_traffic() to later handle */
      received_frame = p;
    }
  }

  return true;
}

uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg)
{
  struct pbuf *p = (struct pbuf *)ref;

  (void)arg; /* unused for this example */

  return pbuf_copy_partial(p, dst, p->tot_len, 0);
}

void service_traffic(void)
{
  /* handle any packet received by tud_network_recv_cb() */
  if (received_frame)
  {
    ethernet_input(received_frame, &netif_data);
    pbuf_free(received_frame);
    received_frame = NULL;
    tud_network_recv_renew();
  }

  sys_check_timeouts();
}

void tud_network_init_cb(void)
{
  /* if the network is re-initializing and we have a leftover packet, we must do a cleanup */
  if (received_frame)
  {
    pbuf_free(received_frame);
    received_frame = NULL;
  }
}
#include "pico/cyw43_arch.h"

#define UDP_PORT 4444
#define BEACON_MSG_LEN_MAX 127
#define BEACON_TARGET "255.255.255.255"
#define BEACON_INTERVAL_MS 1000

void run_udp_beacon() {
    struct udp_pcb* pcb = udp_new();

    ip_addr_t addr;
    ipaddr_aton(BEACON_TARGET, &addr);

    int counter = 0;
    while (true) {
		xSemaphoreTake(wifi_connection_set, portMAX_DELAY);
		xSemaphoreGive(wifi_connection_set);
		if(wifi_scanning_switched_on){
			cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
			break;
		}
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, BEACON_MSG_LEN_MAX+1, PBUF_RAM);
        char *req = (char *)p->payload;
        memset(req, 0, BEACON_MSG_LEN_MAX+1);
        snprintf(req, BEACON_MSG_LEN_MAX, "%d\n", counter);
        err_t er = udp_sendto(pcb, p, &addr, UDP_PORT);
        pbuf_free(p);
        if (er != ERR_OK) {
            //printf("Failed to send UDP packet! error=%d", er);
        } else {
            //printf("Sent packet %d\n", counter);
            counter++;
        }

        // Note in practice for this simple UDP transmitter,
        // the end result for both background and poll is the same

		#if PICO_CYW43_ARCH_POLL
        // if you are using pico_cyw43_arch_poll, then you must poll periodically from your
        // main loop (not from a timer) to check for Wi-Fi driver or lwIP work that needs to be done.
        cyw43_arch_poll();
        sleep_ms(BEACON_INTERVAL_MS);
		#else
        // if you are not using pico_cyw43_arch_poll, then WiFI driver and lwIP work
        // is done via interrupt in the background. This sleep is just an example of some (blocking)
        // work you might be doing.
        sleep_ms(BEACON_INTERVAL_MS);
		#endif
    }
}

char ssid[32] = ""; // Global variable to store ssid
char key[64] = "";  // Global variable to store key
char scan_results[93];
int scan_result(void *env, const cyw43_ev_scan_result_t *result) {
	char result_buf[93];
    if (result) { 
	//xSemaphoreTake(wifi_scan_info_mutex, portMAX_DELAY);
        sprintf(result_buf,"ssid: %-32s rssi: %4d chan: %3d mac: %02x:%02x:%02x:%02x:%02x:%02x sec: %u\n",
            result->ssid, result->rssi, result->channel,
            result->bssid[0], result->bssid[1], result->bssid[2], result->bssid[3], result->bssid[4], result->bssid[5],
            result->auth_mode);
			if (!queue_try_add(&qinbound, result_buf)) {
            //DEBUG(("EQueue full\n"));
        }
	//xSemaphoreGive(wifi_scan_info_mutex);
    }
    return 0;
}
void main_task(__unused void* params)
{
    cyw43_arch_init();
    cyw43_arch_enable_sta_mode();
	cyw43_wifi_pm(&cyw43_state, cyw43_pm_value(CYW43_NO_POWERSAVE_MODE, 20, 1, 1, 1));

    // Connect to the WiFI network - loop until connected
    /*while(cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000) != 0){
        printf("Attempting to connect...\n");
    }
	tcp_app();*/
    // Infinite loop
	while(1){
		absolute_time_t scan_time = nil_time;
		bool scan_in_progress = false;
		while(1) {
			xSemaphoreTake(wifi_connection_set, portMAX_DELAY);
			xSemaphoreGive(wifi_connection_set);
			if(!wifi_scanning_switched_on){
				cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
				break;
			}
			if (absolute_time_diff_us(get_absolute_time(), scan_time) < 0) {
				if (!scan_in_progress) {
					cyw43_wifi_scan_options_t scan_options = {0};
					int err = cyw43_wifi_scan(&cyw43_state, &scan_options, NULL, scan_result);
					if (err == 0) {
						//printf("\nPerforming wifi scan\n");
						scan_in_progress = true;
					} else {
						//printf("Failed to start scan: %d\n", err);
						scan_time = make_timeout_time_ms(5000); // wait 10s and scan again
					}
				} else if (!cyw43_wifi_scan_active(&cyw43_state)) {
					scan_time = make_timeout_time_ms(5000); // wait 10s and scan again
					scan_in_progress = false; 
				}
			}
		}
		if(cyw43_arch_wifi_connect_timeout_ms(ssid, key, CYW43_AUTH_WPA2_AES_PSK, 10000)) {
			//printf("failed to connect.\n");
			//return 1;
		}
		run_udp_beacon();
		//for (;;) {
		//}
		cyw43_wifi_leave(&cyw43_state,CYW43_ITF_STA);
//		else {
			//printf("Connected.\n");

			//extern cyw43_t cyw43_state;
			//auto ip_addr = cyw43_state.netif[CYW43_ITF_STA].ip_addr.addr;
			//printf("IP Address: %lu.%lu.%lu.%lu\n", ip_addr & 0xFF, (ip_addr >> 8) & 0xFF, (ip_addr >> 16) & 0xFF, ip_addr >> 24);
//		}
		// turn on LED to signal connected
		//cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
	}
    cyw43_arch_deinit();
}
//--------------------------------------------------------------------+
// Main
//--------------------------------------------------------------------+

int main(void)
{
  set_sys_clock_khz(200000, true); 
  queue_init(&qinbound, sizeof(scan_results), QSIZE);
  wifi_scan_info_mutex = xSemaphoreCreateMutex();
  wifi_connection_set = xSemaphoreCreateMutex();
  // Create a task for tinyusb device stack
  (void)xTaskCreate(usb_device_task, "usbd", USBD_STACK_SIZE, NULL, 2, &usb_device_taskdef);
  // xTaskCreate()
  //  Create HID task
  (void)xTaskCreate(hid_task, "hid", HID_STACK_SZIE, NULL, 2, &hid_taskdef);
  (void)xTaskCreate(main_task, "wifi_main",5 * configMINIMAL_STACK_SIZE, NULL, 1, &wifi_maindef);
  uxCoreAffinityMask = ( ( 1 << 1 ));
  vTaskCoreAffinitySet( wifi_maindef, uxCoreAffinityMask );
  #if !(TU_CHECK_MCU(ESP32S2) || TU_CHECK_MCU(ESP32S3))
  vTaskStartScheduler();
  #endif
  return 0;
}

#if CFG_TUSB_MCU == OPT_MCU_ESP32S2 || CFG_TUSB_MCU == OPT_MCU_ESP32S3
void app_main(void)
{
  main();
}
#endif
#include <fcntl.h>
#include <sys/types.h>
#include "lwip/sockets.h"
#include "lwip/udp.h"
#include "lwip/debug.h"

void recv_callback_udp(void *arg,
                      struct udp_pcb *upcb,
                      struct pbuf *c,
                      struct ip_addr *addr,
                      u16_t port)
{
    static const char errormsg[] = "sample test msg\n";

    char *command = (char *)(c->payload);
    char *resp = NULL;
    uint16_t resp_len = 0;
	if(queue_try_peek(&qinbound, scan_results))queue_remove_blocking(&qinbound, scan_results);

    if (((command[0] >= 'a' && command[0] <= 'z') ||
         (command[0] >= 'A' && command[0] <= 'Z')) &&
        (command[(c->len) - 1] == '\n'))
    {
        resp = scan_results;
        resp_len = sizeof(scan_results) - 1;
    }

    pbuf_free(c);

    if (resp != NULL) {
        struct pbuf *r = pbuf_alloc(PBUF_TRANSPORT, resp_len, PBUF_REF);
        if (r != NULL) {
            r->payload = resp;
            r->len = resp_len;
            err_t err = udp_sendto(upcb, r, addr, port);
            pbuf_free(r);
        }
    }
}

void udp_echo_init(void)
{
    struct udp_pcb * pcb;

    /* get new pcb */
    pcb = udp_new();
    if (pcb == NULL) {
        //LWIP_DEBUGF(UDP_DEBUG, ("udp_new failed!\n"));
        return;
    }

    /* bind to any IP address on port 7 */
    if (udp_bind(pcb, INADDR_ANY, 2542) != ERR_OK) {
        //LWIP_DEBUGF(UDP_DEBUG, ("udp_bind failed!\n"));
        return;
    }

    /* set udp_echo_recv() as callback function
       for received packets */
    udp_recv(pcb, recv_callback_udp, NULL);
}
int tcp_app()
{
  udp_echo_init();
  int i;
  int s;
  int c;
  int port = 2542;
  struct sockaddr_in address;
  s = lwip_socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
  {
    perror("socket");
    return 1;
  }
  i = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof i);
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);
  address.sin_family = AF_INET;
  if (bind(s, (struct sockaddr *)&address, sizeof(address)) < 0)
  {
    perror("bind");
    return 1;
  }
  //printf("%s,%d\n", __func__, __LINE__);
  if (listen(s, 1) < 0)
  {
    perror("listen");
    return 1;
  }

  fd_set conn;
  int maxfd = 0;
  FD_ZERO(&conn);
  FD_SET(s, &conn);
  maxfd = s;
  //printf("%s,%d\n", __func__, __LINE__);
  while (1)
  {
    fd_set read = conn, except = conn;
    int fd;
    if (select(maxfd + 1, &read, 0, &except, 0) < 0)
    {
      perror("select");
      break;
    }
    for (fd = 0; fd <= maxfd; ++fd)
    {
      if (FD_ISSET(fd, &read))
      {
        if (fd == s)
        {
          int newfd;
          socklen_t nsize = sizeof(address);

          newfd = accept(s, (struct sockaddr *)&address, &nsize);

          //               if (verbose)
          //printf("connection accepted - fd %d\n", newfd);
          if (newfd < 0)
          {
            perror("accept");
          }
          else
          {
            //printf("setting TCP_NODELAY to 1\n");
            int flag = 1;
            int optResult = setsockopt(newfd,
                                       IPPROTO_TCP,
                                       TCP_NODELAY,
                                       (char *)&flag,
                                       sizeof(int));
            if (optResult < 0)
              perror("TCP_NODELAY error");
            if (newfd > maxfd)
            {
              maxfd = newfd;
            }
            FD_SET(newfd, &conn);
          }
        }
        else if (handle_data(fd, NULL))
        {
          close(fd);
          FD_CLR(fd, &conn);
        }
      }
      else if (FD_ISSET(fd, &except))
      {
        close(fd);
        FD_CLR(fd, &conn);
        if (fd == s)
          break;
      }
    }
  }
  return 0;
}
int tcp_app_runloop()
{
  return 0;
}

int handle_data(int fd, fd_set *conn) {
    char buffer[1024];
    ssize_t bytes_received, bytes_sent;

    // Receive data from the client
    bytes_received = recv(fd, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        return 1; // Close the connection
    } else {
        if (strncmp(buffer, "setwifi", 7) == 0) {
            // Extract ssid and key from the input buffer
            char *ptr = buffer + 8; // Skip "setwifi "
            int ssid_len = 0, key_len = 0;
            while (*ptr != '\0') {
                if (strncmp(ptr, "ssid:", 5) == 0) {
                    ptr += 5; // Skip "ssid:"
                    ssid_len = strcspn(ptr, " ");
                    memcpy(ssid, ptr, ssid_len);
                    //ssid[ssid_len] = '\0'; // Ensure null-terminated string
                    ptr += ssid_len; // Move past the ssid
                } else if (strncmp(ptr, "key:", 4) == 0) {
                    ptr += 4; // Skip "key:"
                    key_len = strcspn(ptr, "\r\n");
                    memcpy(key, ptr, key_len);
                    //key[key_len] = '\0'; // Ensure null-terminated string
                    ptr += key_len; // Move past the key
                } else {
                    // Move to the next token if not ssid or key
                    ptr += strcspn(ptr, " \r\n") + 1;
                }
            }
			xSemaphoreTake(wifi_connection_set, portMAX_DELAY);
			wifi_scanning_switched_on=false;
			xSemaphoreGive(wifi_connection_set);
        } else if (strncmp(buffer, "getcred", 7) == 0) {
            // Prepare the response with ssid and key details
            //char response[100];
            snprintf(buffer, sizeof(buffer), "ssid:%s key:%s \r\n\0", ssid, key);

            // Send back the response to the client
            bytes_sent = send(fd, buffer, strlen(buffer), 0);
        } else if (strncmp(buffer, "diswifi", 7) == 0) {
            xSemaphoreTake(wifi_connection_set, portMAX_DELAY);
			wifi_scanning_switched_on=true;
			xSemaphoreGive(wifi_connection_set);
        }

        // Clear the buffer after it is sent
        memset(buffer, 0, sizeof(buffer));
    }

    return 0; // Continue the connection
}
/* This function initializes this lwIP test. When NO_SYS=1, this is done in
 * the main_loop context (there is no other one), when NO_SYS=0, this is done
 * in the tcpip_thread context */
static void
test_init(void *arg)
{ /* remove compiler warning */
#if NO_SYS
  LWIP_UNUSED_ARG(arg);
#else  /* NO_SYS */
  sys_sem_t *init_sem;
  LWIP_ASSERT("arg != NULL", arg != NULL);
  init_sem = (sys_sem_t *)arg;
#endif /* NO_SYS */

  /* init randomizer again (seed per thread) */
  srand((unsigned int)time(NULL));
  //printf("task %s,%d\n", __func__, __LINE__);
  /* init network interfaces */
  // test_netif_init();

  struct netif *netif = &netif_data;
  /* the lwip virtual MAC address must be different from the host's; to ensure this, we toggle the LSbit */
  netif->hwaddr_len = sizeof(tud_network_mac_address);
  memcpy(netif->hwaddr, tud_network_mac_address, sizeof(tud_network_mac_address));
  netif->hwaddr[5] ^= 0x01;
  netif = netif_add(netif, &ipaddr, &netmask, &gateway, NULL, netif_init_cb, ip_input);
  netif_set_default(netif);

  /* init apps */
  // apps_init();

#if !NO_SYS
  //printf("task %s,%d\n", __func__, __LINE__);
  sys_sem_signal(init_sem);
  //printf("task %s,%d\n", __func__, __LINE__);
#endif /* !NO_SYS */
}

// USB Device Driver task
// This top level thread process all usb events and invoke callbacks
void usb_device_task(void *param)
{
  (void)param;

  // This should be called after scheduler/kernel is started.
  // Otherwise it could cause kernel issue since USB IRQ handler does use RTOS queue API.
  tusb_init();

  // RTOS forever loop
  while (1)
  {
    // tinyusb device task
    tud_task();
    service_traffic();
  }
}


void hid_task(void *param)
{
  (void)param;
  //printf("%s,%d\n", __func__, __LINE__);
  err_t err;
  sys_sem_t init_sem;
  err = sys_sem_new(&init_sem, 0);
  tcpip_init(test_init, &init_sem);
  /* we have to wait for initialization to finish before
   * calling update_adapter()! */
  sys_sem_wait(&init_sem);
  sys_sem_free(&init_sem);

  while (!netif_is_up(&netif_data))
    ;
  while (dhserv_init(&dhcp_config) != ERR_OK)
    ;
  while (dnserv_init(&ipaddr, 53, dns_query_proc) != ERR_OK)
    ;
  // Initialise web server
  //httpd_init();
  tcp_app();
  //udp_echo_init();
  // Configure SSI and CGI handler
  //ssi_init(); 
  //cgi_init();
}