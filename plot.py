import warnings

import numpy as np
from matplotlib.axes import Axes
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import pandas as pd


def ax_common(ax: Axes, title=None, ylabel=None, xlabel=None, ncol=1, legend=True, pad=None, loc='best', ylim=True, partial=False, rotation=0, fontsize=None, ynormal=True, grid=True, percentage=False):
    ax.set_xlabel(xlabel, fontsize=fontsize)
    ax.set_ylabel(ylabel, fontsize=fontsize)
    if legend:
        ax.legend(ncol=ncol, loc=loc, fontsize=fontsize).set_title(False)
    else:
        h, l = ax.get_legend_handles_labels()
        if l:
            ax.legend().set_visible(False)
    ax.set_title(title, pad=pad, fontsize=fontsize)
    if ynormal:
        ax.set_yticks(np.arange(0, 1.1, .1))
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['bottom'].set_visible(partial)
    ax.spines['left'].set_visible(partial)
    ax.set_axisbelow(True)
    if grid:
        ax.yaxis.grid(color='lightgray', linestyle='--', linewidth=.5)
    if ylim:
        ax.set_ylim(top=1, bottom=0)
    if rotation:
        for item in ax.get_xticklabels():
            item.set_rotation(rotation)
    if percentage:
        ax.yaxis.set_major_formatter(PercentFormatter(xmax=1, decimals=0))

def fig_common(fig, handles=None, labels=None, ncol=3, borderaxespad=None, loc='upper center', title=None, y=1.2, wspace=None, hspace=None, ltitle=None):
    # fig.legend(handles, labels, fontsize=18, loc='upper center', ncol=ncol, borderaxespad=borderaxespad)
    if handles is not None:
        fig.legend(handles=handles, labels=labels, loc=loc, ncol=ncol, borderaxespad=borderaxespad, framealpha=1, title=ltitle)
    if title is not None:
        fig.suptitle(title, y=y)
    if wspace and hspace:
        fig.subplots_adjust(hspace=hspace, wspace=wspace)
    elif wspace:
        fig.subplots_adjust(wspace=wspace)

def boxplot(data, color, offset, linewidth=.5, ax: Axes=None, label=None, widths=.25, **kwargs):
    if ax is None:
        ax = plt.gca()
    handle = mpatches.Patch(color=color, label=label)
    ax.boxplot(
        data, positions=np.arange(1, len(data)+1) + offset, widths=widths, patch_artist=True,
        flierprops=dict(marker='.', markerfacecolor=color, markersize=2, linestyle='none', markeredgecolor=color),
        boxprops=dict(linestyle='-', linewidth=linewidth, facecolor=(0, 0, 0, 0), zorder=10, color=color),
        medianprops=dict(linestyle='-', linewidth=linewidth, color=color),
        whiskerprops=dict(linewidth=linewidth, color=color),
        capprops=dict(linewidth=linewidth, color=color),
        **kwargs
    )
    return handle

def boxplotdf(df, col, groupby, *args, **kwargs):
    data = [g[col][pd.notnull(g[col])] for i, g in df.groupby(groupby)]
    return boxplot(data, *args, **kwargs)
