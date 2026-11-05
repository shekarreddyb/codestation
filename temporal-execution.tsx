import {Line, makeScene2D, Rect, Txt} from '@motion-canvas/2d';
import {all, createRef, waitFor} from '@motion-canvas/core';

// One lane per participant. All X coordinates are stable.
const lanes = {
  caller: {x: -720, title: 'Caller', color: '#2563eb'},
  server: {x: -240, title: 'Temporal Server', color: '#7c3aed'},
  workflow: {x: 240, title: 'Workflow Worker', color: '#0891b2'},
  activity: {x: 720, title: 'Activity Worker', color: '#059669'},
} as const;

type LaneId = keyof typeof lanes;

type Message = {
  from: LaneId;
  to: LaneId;
  label: string;
  note: string;
  color: string;
};

// Edit this array to change the story without changing drawing code.
const messages: Message[] = [
  {
    from: 'caller',
    to: 'server',
    label: 'StartWorkflowExecution',
    note: 'Server starts the execution and records history events.',
    color: '#60a5fa',
  },
  {
    from: 'workflow',
    to: 'server',
    label: 'PollWorkflowTaskQueue',
    note: 'A workflow worker long-polls its task queue.',
    color: '#22d3ee',
  },
  {
    from: 'server',
    to: 'workflow',
    label: 'Workflow Task',
    note: 'The poll returns a task with workflow history.',
    color: '#a78bfa',
  },
  {
    from: 'workflow',
    to: 'server',
    label: 'ScheduleActivityTask command',
    note: 'Workflow code runs or replays and emits a command.',
    color: '#22d3ee',
  },
  {
    from: 'activity',
    to: 'server',
    label: 'PollActivityTaskQueue',
    note: 'An activity worker long-polls the activity queue.',
    color: '#34d399',
  },
  {
    from: 'server',
    to: 'activity',
    label: 'Activity Task',
    note: 'The server returns an activity task to that poll.',
    color: '#c4b5fd',
  },
  {
    from: 'activity',
    to: 'server',
    label: 'Activity Completed',
    note: 'The result is recorded in workflow history.',
    color: '#34d399',
  },
  {
    from: 'server',
    to: 'workflow',
    label: 'Next Workflow Task',
    note: 'The worker is scheduled to process the activity result.',
    color: '#a78bfa',
  },
  {
    from: 'workflow',
    to: 'server',
    label: 'CompleteWorkflowExecution',
    note: 'The worker returns a completion command; the server persists it.',
    color: '#22d3ee',
  },
];

export default makeScene2D(function* (view) {
  view.fill('#0b1220');

  // Title at the top and explanatory caption at the bottom.
  const caption = createRef<Txt>();

  view.add(
    <>
      <Txt
        text={'How Temporal Executes a Workflow'}
        y={-468}
        fontSize={52}
        fontWeight={700}
        fill={'#f8fafc'}
      />
      <Txt
        ref={caption}
        text={'Follow one request through the server and workers.'}
        y={492}
        fontSize={25}
        fill={'#cbd5e1'}
      />
    </>,
  );

  // Create stable participant headers and vertical lifelines.
  for (const lane of Object.values(lanes)) {
    view.add(
      <>
        <Rect
          x={lane.x}
          y={-352}
          width={310}
          height={74}
          radius={14}
          fill={lane.color}
        >
          <Txt text={lane.title} fontSize={28} fill={'#ffffff'} />
        </Rect>
        <Line
          points={[[lane.x, -310], [lane.x, 460]]}
          stroke={'#475569'}
          lineWidth={3}
          lineDash={[9, 10]}
          opacity={0.75}
        />
      </>,
    );
  }

  // A generator helper: draw one arrow, reveal its label, update caption.
  function* animateMessage(message: Message, index: number) {
    const arrow = createRef<Line>();
    const label = createRef<Txt>();

    const fromX = lanes[message.from].x;
    const toX = lanes[message.to].x;
    const y = -260 + index * 83;

    view.add(
      <>
        <Line
          ref={arrow}
          points={[[fromX, y], [toX, y]]}
          stroke={message.color}
          lineWidth={5}
          endArrow
          arrowSize={17}
          end={0}
        />
        <Txt
          ref={label}
          x={(fromX + toX) / 2}
          y={y - 24}
          text={message.label}
          fontSize={21}
          fontWeight={600}
          fill={message.color}
          opacity={0}
        />
      </>,
    );

    yield* all(
      arrow().end(1, 0.7),
      label().opacity(1, 0.35),
      caption().text(message.note, 0.4),
    );

    // Reading time matters: don't rush the diagram.
    yield* waitFor(0.55);
  }

  // The complete story is driven by the messages array.
  for (const [index, message] of messages.entries()) {
    yield* animateMessage(message, index);
  }

  yield* waitFor(1);
});
