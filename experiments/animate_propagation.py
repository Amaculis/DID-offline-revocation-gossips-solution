
from __future__ import annotations

import argparse
import os
import random
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import simpy
from matplotlib.lines import Line2D
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sim.common.issuer import Issuer
from sim.common.network import assign_dead_nodes, assign_initial_states, build_graph
from sim.strategies.holder_gossip import HolderGossipNode, HolderNode
from sim.strategies.pull import PullNode
from sim.strategies.push import PushNode
from sim.strategies.push_holder_gossip import PushHolderGossipNode, PushHolderNode

KNOWS, BLIND = "#1D9E75", "#D85A30"
TITLES = {
    "PULL": "PULL\nscanner polls the issuer",
    "PUSH": "PUSH\nissuer notifies online scanners",
    "GOSSIP": "GOSSIP + holders\nscanners and visitors share lists",
    "MIXED": "MIXED\npush + gossip + holders",
}
REVOKE_AT = 600  # seconds


def build_scenario(strategy: str, n: int, hours: float, seed: int):
    rng = random.Random(seed)
    env = simpy.Environment()
    ttl = 4 * 3600
    issuer = Issuer(env, revocation_rate=1e-12, ttl=ttl, num_credentials=n * 10,
                    rng=random.Random(rng.randint(0, 2**31)))

    graph = build_graph(n, seed=seed)
    dead = assign_dead_nodes(n, 0.3, rng)
    online = assign_initial_states(n, 0.4, rng, dead_nodes=dead)
    mean_on, mean_off = 1800, 7200
    n_seeds = max(1, int(n * 0.05))

    def node_rng():
        return random.Random(rng.randint(0, 2**31))

    common = dict(env=env, issuer=issuer, mean_online_duration=mean_on, mean_offline_duration=mean_off)
    verifiers = []

    for vid in range(n):
        kw = dict(common, node_id=vid, is_online=online[vid], rng=node_rng(), is_dead=vid in dead)
        if strategy == "PULL":
            node = PullNode(**kw)
            node.awareness_times = {}
        elif strategy == "PUSH":
            node = PushNode(**kw)
            issuer.register(node)
        elif strategy == "GOSSIP":
            node = HolderGossipNode(**kw, contact_rate=1 / 600, is_seed=vid < n_seeds)
        else:
            node = PushHolderGossipNode(**kw, contact_rate=1 / 600, is_seed=vid < n_seeds)
            issuer.register(node)
        verifiers.append(node)

    if strategy in ("GOSSIP", "MIXED"):
        for vid, v in enumerate(verifiers):
            v.peers = [verifiers[nbr] for nbr in graph.neighbors(vid)]
        holder_cls = HolderNode if strategy == "GOSSIP" else PushHolderNode
        for hid in range(n // 2):  # festival visitors carrying their tickets around
            h = holder_cls(node_id=n + hid, env=env, issuer=issuer, is_online=rng.random() > 0.4,
                           rng=node_rng(), mean_online_duration=mean_on, mean_offline_duration=mean_off,
                           mean_presentation_interval=3600, is_dead=False)
            h.verifiers = rng.sample(verifiers, min(6, n))

    def revoke():
        yield env.timeout(REVOKE_AT)
        issuer._do_revoke()

    env.process(revoke())
    return env, verifiers, issuer, graph, dead


def knows(node, cred_id) -> bool:
    return node.cached_list is not None and cred_id in node.cached_list.revoked_ids


def collect(strategy: str, n: int, hours: float, step: int, seed: int):
    env, verifiers, issuer, graph, dead = build_scenario(strategy, n, hours, seed)
    frames = []
    for t in range(0, int(hours * 3600) + 1, step):
        env.run(until=max(t, 1))
        if not issuer.revocation_log:
            frames.append([False] * n)
            continue
        cred = issuer.revocation_log[0].credential_id
        frames.append([knows(v, cred) for v in verifiers])
    return frames, graph, dead


def render(all_frames, graph, dead, hours, step, out_path, fps):
    pos = nx.spring_layout(graph, seed=7, k=0.35)
    strategies = list(all_frames)
    n = graph.number_of_nodes()
    alive = [i for i in range(n) if i not in dead]
    dead_l = sorted(dead)
    n_frames = len(next(iter(all_frames.values())))

    imgs = []
    for f in range(n_frames):
        fig, axes = plt.subplots(2, 2, figsize=(10, 10.2))
        t = f * step
        for ax, strat in zip(axes.flat, strategies):
            state = all_frames[strat][f]
            nx.draw_networkx_edges(graph, pos, ax=ax, edge_color="#cccccc", width=0.6)
            for nodes, marker in ((alive, "o"), (dead_l, "s")):
                nx.draw_networkx_nodes(
                    graph, pos, nodelist=nodes, ax=ax, node_shape=marker, node_size=70,
                    node_color=[KNOWS if state[i] else BLIND for i in nodes],
                    edgecolors="white", linewidths=0.8,
                )
            informed = sum(state)
            ax.set_title(f"{TITLES[strat]}\n{informed}/{n} informed ({informed / n:.0%})", fontsize=11)
            ax.axis("off")
        status = "ticket not revoked yet" if t < REVOKE_AT else "red = still accepts it"
        fig.suptitle(f"Stolen ticket revoked at 00:10   |   t = {t // 3600:02d}:{(t % 3600) // 60:02d}   |   {status}",
                     fontsize=13, fontweight="bold")
        fig.legend(handles=[
            Line2D([], [], marker="o", ls="", color=KNOWS, label="knows about revocation"),
            Line2D([], [], marker="o", ls="", color=BLIND, label="blind (accepts revoked ticket)"),
            Line2D([], [], marker="s", ls="", color="#888888", label="square = no internet at all"),
        ], loc="lower center", ncol=3, frameon=False, fontsize=10)
        fig.tight_layout(rect=(0, 0.04, 1, 0.95))
        fig.canvas.draw()
        imgs.append(Image.fromarray(np.asarray(fig.canvas.buffer_rgba())[..., :3]))
        plt.close(fig)

    imgs = [im.convert("P", palette=Image.ADAPTIVE) for im in imgs]
    durations = [int(1000 / fps)] * len(imgs)
    durations[-1] = 2500  # hold the final state
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    imgs[0].save(out_path, save_all=True, append_images=imgs[1:], duration=durations, loop=0, optimize=True)
    print(f"Saved -> {out_path}  ({len(imgs)} frames)")


def main():
    ap = argparse.ArgumentParser(description="Animate revocation propagation for each strategy")
    ap.add_argument("--nodes", type=int, default=60)
    ap.add_argument("--hours", type=float, default=12)
    ap.add_argument("--step", type=int, default=900, help="seconds of simulated time per frame")
    ap.add_argument("--fps", type=int, default=6)
    ap.add_argument("--seed", type=int, default=3)
    ap.add_argument("--output", default="docs/img/propagation.gif")
    args = ap.parse_args()

    all_frames, graph, dead = {}, None, None
    for strat in TITLES:
        print(f"Simulating {strat} ...")
        all_frames[strat], graph, dead = collect(strat, args.nodes, args.hours, args.step, args.seed)
    render(all_frames, graph, dead, args.hours, args.step, args.output, args.fps)


if __name__ == "__main__":
    main()
