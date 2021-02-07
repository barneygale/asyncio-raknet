import asyncio
import collections
import io

from asyncio_raknet.packets import *


class Task(object):
    ticks = None
    retries = None

    def __init__(self, obj, ticks, retries):
        assert obj is not None
        self.obj = obj
        self.max_ticks = ticks
        self.max_retries = retries
        self.reset()

    @property
    def alive(self):
        return self.retries >= 0

    @property
    def active(self):
        return self.alive and self.ticks == 0

    def reset(self):
        self.ticks = 0
        self.retries = self.max_retries

    def stop(self):
        self.retries = -1

    def tick(self):
        self.ticks -= 1
        if self.ticks == -1:
            self.ticks += self.max_ticks
            self.retries -= 1


class Protocol(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
        self.mtu = 1446  # TODO: review
        self.online = False
        self.transport = None
        self.local_address = None
        self.remote_address = None
        self.guid = GUID.random()
        self.version = 10
        self.read_queue = asyncio.Queue()
        self.read_frame_set_idx = 0
        self.read_order_idx = 0
        self.read_order_chan = {}
        self.read_fragment_chans = collections.defaultdict(dict)
        self.write_offline_task = None
        self.write_online_tasks = []
        self.write_reliable_idx = 0
        self.write_order_idx = 0
        self.write_frame_set_idx = 0
        self.write_frame_set_chan = {}
        self.write_fragment_chan = 0

    def connection_made(self, transport):
        family = transport.get_extra_info('socket').family
        self.transport = transport
        self.local_address = Address(family, *transport.get_extra_info('sockname'))
        self.remote_address = Address(family, *transport.get_extra_info('peername'))
        asyncio.Task(self.tick_forever())

    def datagram_received(self, data, addr=None):
        buff = io.BytesIO(data)
        ident = data[0]

        if ident & 0xF0 == 0x80:
            packet = FrameSet.unpack(buff)
        else:
            packet = packet_types[ident].unpack(buff)

        if type(packet) is ConnectedPing:
            receipt = ConnectedPong(packet.local_time, 0)
            self.write(receipt)

        elif type(packet) in (ACK, NACK):
            # Find reliable indices from frame set indices
            reliable_indices = []
            for frame_set_index in packet.indices:
                if frame_set_index in self.write_frame_set_chan:
                    reliable_indices.extend(self.write_frame_set_chan[frame_set_index])
                    del self.write_frame_set_chan[frame_set_index]

            # Find frames from reliable indices
            for task in self.write_online_tasks:
                frame = task.obj
                if frame.reliable_idx in reliable_indices:
                    # ACK: Discard frame
                    if type(packet) is ACK:
                        task.stop()

                    # NAK: Bring frame to front of queue
                    else:
                        task.reset()

        elif type(packet) is FrameSet:
            for frame in packet.frames:

                # Handle fragmentation
                if frame.fragmented:
                    fragment_chan = self.read_fragment_chans[frame.fragment_chan]
                    fragment_chan[frame.fragment_idx] = frame
                    if len(fragment_chan) != frame.fragment_count:
                        continue
                    fragments = [fragment_chan[idx] for idx in range(frame.fragment_count)]
                    fragment_chan.clear()
                    frame = Frame.from_fragments(fragments)

                # Handle ordering
                if frame.ordered:
                    self.read_order_chan[self.read_order_idx] = frame
                    while self.read_order_idx in self.read_order_chan:
                        frame = self.read_order_chan.pop(self.read_order_idx)
                        self.datagram_received(frame.payload)
                        self.read_order_idx += 1
                else:
                    self.datagram_received(frame.payload)

            # Send NAK
            nak_indices = list(range(self.read_frame_set_idx, packet.idx))
            if nak_indices:
                receipt = NACK(indices=nak_indices)
                self.transport.sendto(receipt.pack())

            # Send ACK
            receipt = ACK(indices=[packet.idx])
            self.transport.sendto(receipt.pack())

            # Update frame set index
            self.read_frame_set_idx = packet.idx + 1

        else:
            self.read_queue.put_nowait(packet)

    async def read(self):
        return await self.read_queue.get()

    def write(self, packet):
        data = packet.pack()

        # Set offline task if we're offline
        if not self.online:
            self.write_offline_task = Task(data, ticks=20, retries=5)
            return

        frames = []
        mtu = self.mtu - 60

        # Simple case: no need to fragment
        if len(data) <= mtu:
            # Evil hack: send pings/pongs as unreliable + unordered!
            if data[0] in (0, 3):
                frames.append(Frame(data))

            # Otherwise send reliable + ordered
            else:
                frames.append(Frame(
                    payload=data,
                    reliable_idx=self.write_reliable_idx,
                    order_idx=self.write_order_idx))
                self.write_reliable_idx += 1
                self.write_order_idx += 1

        # Otherwise split the payload into fragments
        else:
            # Split
            fragments = []
            while data:
                fragments.append(data[:mtu])
                data = data[mtu:]

            # Send fragments ordered + reliable
            for fragment_idx, fragment in enumerate(fragments):
                frame = Frame(
                    payload=fragment,
                    reliable_idx=self.write_reliable_idx,
                    order_idx=self.write_order_idx,
                    fragment_idx=fragment_idx,
                    fragment_count=len(fragments),
                    fragment_chan=self.write_fragment_chan)
                frames.append(frame)
                self.write_reliable_idx += 1
            self.write_fragment_chan = (self.write_fragment_chan + 1) % 32
            self.write_order_idx += 1

        # Queue a task for each frame
        for frame in frames:
            retries = 5 if frame.reliable else 0
            self.write_online_tasks.append(Task(frame, ticks=20, retries=retries))

    def tick(self):
        # Tick/run offline task if we're offline
        if not self.online:
            if self.write_offline_task and self.write_offline_task.alive:
                if self.write_offline_task.active:
                    self.transport.sendto(self.write_offline_task.obj)
                self.write_offline_task.tick()
            return

        # Tick online tasks and find active frames
        frames = []
        tasks = []
        for task in self.write_online_tasks:
            if task.alive:
                if task.active:
                    frames.append(task.obj)
                task.tick()
                tasks.append(task)
        self.write_online_tasks[:] = tasks

        # Combine frames into frame sets
        while frames:
            frame_set = FrameSet(self.write_frame_set_idx, [])
            frame_set_size = len(frame_set.pack())
            reliable_indices = []
            while frames:
                frame = frames.pop(0)
                frame_size = len(frame.pack())

                # Full frame set?
                if (frame_set_size + frame_size) > (self.mtu - 28):
                    break

                # Add the frame
                frame_set.frames.append(frame)
                frame_set_size += frame_size
                if frame.reliable:
                    reliable_indices.append(frame.reliable_idx)

            # Record reliable indices for ACKs/NAKs
            self.write_frame_set_chan[self.write_frame_set_idx] = reliable_indices
            self.write_frame_set_idx += 1

            # Send the frame set
            self.transport.sendto(frame_set.pack())

    async def tick_forever(self):
        while not self.transport.is_closing():
            self.tick()
            await asyncio.sleep(0.05)
